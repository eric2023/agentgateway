// SPDX-License-Identifier: Apache-2.0
// Process attribution — ported from agw_addon.py _lookup_peer().
// Identifies the agent process behind a REDIRECTed connection by:
//   1. Finding the socket inode in /proc/net/tcp+tcp6 by local port
//   2. Scanning /proc/*/fd/ to find which PID owns the socket
//   3. Walking the parent chain to find the real agent process
//   4. Reading AGENTGATEWAY_* env vars from /proc/<pid>/environ
use std::net::IpAddr;
use std::sync::{Mutex, LazyLock};
use std::collections::HashSet;
use std::fs;
use std::time::{Duration, Instant};

const LISTEN_PORT: u16 = 8444;
const CACHE_TTL: Duration = Duration::from_secs(5); // reduced from 30s to 5s (C09)

struct CacheEntry {
    agent_pid: Option<i32>,
    agent_comm: Option<String>,
    app_name: Option<String>,
    agent_id: Option<String>,
    session_id: Option<String>,
    ts: Instant,
}
static CACHE: LazyLock<Mutex<std::collections::HashMap<(u16, IpAddr), CacheEntry>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

/// Tool processes — not the real agent. Skip these when walking the parent chain.
const TOOL_PROCESSES: &[&str] = &[
    "curl", "wget",
    "python", "python3", "python3.11", "python3.10", "python3.9", "python3.8",
    "node", "nodejs", "deno", "bun",
    "bash", "sh", "zsh", "dash", "fish", "ksh", "tcsh", "csh",
    "env", "nohup", "timeout", "xargs", "nice", "ionice", "stdbuf",
    "exec", "tee", "cat", "dd", "strace", "ltrace", "valgrind",
    "supervisord", "systemd", "init",
];

/// Look up the peer process for a given client connection.
/// Uses (peer_port, peer_ip) as cache key to reduce port-reuse misattribution (C09).
/// Returns (agent_pid, agent_comm, app_name, agent_id, session_id).
pub type PeerInfo = (Option<i32>, Option<String>, Option<String>, Option<String>, Option<String>);

/// Look up the peer process for a given client connection.
/// Uses (peer_port, peer_ip) as cache key to reduce port-reuse misattribution (C09).
/// Returns (agent_pid, agent_comm, app_name, agent_id, session_id).
pub fn lookup_peer(peer_port: u16, peer_ip: IpAddr) -> PeerInfo {
    // Check cache
    {
        let cache = CACHE.lock().unwrap();
        if let Some(entry) = cache.get(&(peer_port, peer_ip)) {
            if entry.ts.elapsed() < CACHE_TTL {
                return (
                    entry.agent_pid,
                    entry.agent_comm.clone(),
                    entry.app_name.clone(),
                    entry.agent_id.clone(),
                    entry.session_id.clone(),
                );
            }
        }
    }

    // Find socket inode
    let inode = match find_socket_inode(peer_port, LISTEN_PORT) {
        Some(i) => i,
        None => {
            return (None, None, None, None, None);
        }
    };

    // Find PID owning this socket
    let pid = match find_pid_by_inode(&inode) {
        Some(p) => p,
        None => {
            return (None, None, None, None, None);
        }
    };

    // Resolve agent process (walk parent chain)
    let (agent_pid, agent_comm) = resolve_agent_process(pid);

    // Read env vars from the resolved agent process, not the tool process (R3-9)
    let env_pid = agent_pid.unwrap_or(pid);
    let (mut app_name, mut agent_id, mut session_id) = read_env_vars(env_pid);

    // Fall back to executable basename if AGENTGATEWAY_APP_NAME not set
    if app_name.is_none() {
        if let Some(apid) = agent_pid {
            app_name = read_exe_basename(apid).or_else(|| agent_comm.clone());
        }
    }

    // Generate stable agent_id/session_id from app_name if not set
    let stable_name = app_name.clone()
        .or_else(|| agent_comm.clone())
        .unwrap_or_else(|| "unknown".to_string());
    if agent_id.is_none() {
        agent_id = Some(format!("agent-{}", stable_name));
    }
    if session_id.is_none() {
        session_id = Some(format!("session-{}", stable_name));
    }

    // Cache the result
    {
        let mut cache = CACHE.lock().unwrap();
        cache.insert((peer_port, peer_ip), CacheEntry {
            agent_pid,
            agent_comm: agent_comm.clone(),
            app_name: app_name.clone(),
            agent_id: agent_id.clone(),
            session_id: session_id.clone(),
            ts: Instant::now(),
        });
    }

    (agent_pid, agent_comm, app_name, agent_id, session_id)
}

/// Find socket inode by local port, scanning /proc/net/tcp and tcp6.
fn find_socket_inode(peer_port: u16, exclude_port: u16) -> Option<String> {
    for proc_file in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = fs::read_to_string(proc_file) {
            for (i, line) in content.lines().enumerate() {
                if i == 0 {
                    continue; // skip header
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 10 {
                    continue;
                }
                if parts[3] != "01" {
                    continue; // not ESTABLISHED
                }
                let local_port = match parts[1].split(':').nth(1) {
                    Some(s) => match u16::from_str_radix(s, 16) {
                        Ok(p) => p,
                        Err(_) => continue,
                    },
                    None => continue,
                };
                if local_port != peer_port {
                    continue;
                }
                let remote_port = match parts[2].split(':').nth(1) {
                    Some(s) => match u16::from_str_radix(s, 16) {
                        Ok(p) => p,
                        Err(_) => continue,
                    },
                    None => continue,
                };
                if remote_port == exclude_port {
                    continue;
                }
                return Some(parts[9].to_string());
            }
        }
    }
    None
}

/// Scan /proc/*/fd/ to find which PID owns a socket with the given inode.
fn find_pid_by_inode(inode: &str) -> Option<i32> {
    let search_link = format!("socket:[{}]", inode);
    let my_pid = std::process::id() as i32;

    let proc_dirs = fs::read_dir("/proc").ok()?;
    for entry in proc_dirs.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let pid: i32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if pid == my_pid {
            continue;
        }
        let fd_dir = format!("/proc/{}/fd", pid);
        if let Ok(fds) = fs::read_dir(&fd_dir) {
            for fd in fds.flatten() {
                if let Ok(link) = fs::read_link(fd.path()) {
                    if link.to_string_lossy() == search_link {
                        return Some(pid);
                    }
                }
            }
        }
    }
    None
}

/// Read /proc/<pid>/comm
fn read_comm(pid: i32) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Read PPid from /proc/<pid>/status
fn read_ppid(pid: i32) -> Option<i32> {
    let status = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if line.starts_with("PPid:") {
            return line.split_whitespace().nth(1).and_then(|s| s.parse().ok());
        }
    }
    None
}

/// Walk the parent chain to find the real agent process.
/// Skips tool processes (curl, python3, bash, etc.).
fn resolve_agent_process(direct_pid: i32) -> (Option<i32>, Option<String>) {
    let comm = match read_comm(direct_pid) {
        Some(c) => c,
        None => return (Some(direct_pid), None),
    };

    let tool_set: HashSet<&str> = TOOL_PROCESSES.iter().copied().collect();

    // If the direct process is not a tool, it IS the agent
    if !tool_set.contains(comm.as_str()) {
        return (Some(direct_pid), Some(comm));
    }

    // Walk up the parent chain
    let mut pid = direct_pid;
    let mut visited = HashSet::new();
    while pid != 0 && !visited.contains(&pid) {
        visited.insert(pid);
        let ppid = match read_ppid(pid) {
            Some(p) if p != 1 => p,
            _ => break,
        };
        let parent_comm = match read_comm(ppid) {
            Some(c) => c,
            None => break,
        };
        if !tool_set.contains(parent_comm.as_str()) {
            return (Some(ppid), Some(parent_comm));
        }
        pid = ppid;
    }

    (Some(direct_pid), Some(comm))
}

/// Read AGENTGATEWAY_* env vars from /proc/<pid>/environ
fn read_env_vars(pid: i32) -> (Option<String>, Option<String>, Option<String>) {
    let environ = match fs::read(format!("/proc/{}/environ", pid)) {
        Ok(e) => e,
        Err(_) => return (None, None, None),
    };

    let mut app_name = None;
    let mut agent_id = None;
    let mut session_id = None;

    for entry in environ.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }
        let entry_str = String::from_utf8_lossy(entry);
        if let Some(val) = entry_str.strip_prefix("AGENTGATEWAY_APP_NAME=") {
            app_name = Some(val.to_string());
        } else if let Some(val) = entry_str.strip_prefix("AGENTGATEWAY_AGENT_ID=") {
            agent_id = Some(val.to_string());
        } else if let Some(val) = entry_str.strip_prefix("AGENTGATEWAY_SESSION_ID=") {
            session_id = Some(val.to_string());
        }
    }

    (app_name, agent_id, session_id)
}

/// Read the executable basename for a PID.
fn read_exe_basename(pid: i32) -> Option<String> {
    let exe = fs::read_link(format!("/proc/{}/exe", pid)).ok()?;
    exe.file_name()
        .map(|n| n.to_string_lossy().to_string())
}
