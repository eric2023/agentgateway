// SPDX-License-Identifier: Apache-2.0
// Process attribution — ported from agw_addon.py _lookup_peer().
// Identifies the agent process behind a REDIRECTed connection by:
//   1. Finding the socket inode in /proc/net/tcp+tcp6 by local port
//   2. Scanning /proc/*/fd/ to find which PID owns the socket
//   3. Walking the parent chain to find the real agent process
//   4. Reading AGENTGATEWAY_* env vars from /proc/<pid>/environ
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, LazyLock};
use std::collections::HashSet;
use std::fs;
use std::time::{Duration, Instant};

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

/// Alias for the lookup_peer return tuple.
pub type PeerInfo = (Option<i32>, Option<String>, Option<String>, Option<String>, Option<String>);

/// Look up the peer process for a given client connection.
/// Uses (peer_port, peer_ip) as cache key to reduce port-reuse misattribution (C09).
/// Returns (agent_pid, agent_comm, app_name, agent_id, session_id).
pub fn lookup_peer(peer_port: u16, peer_ip: IpAddr, orig_dst: SocketAddr) -> PeerInfo {
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

    // Find PID by scanning process fd tables.
    // iptables REDIRECT creates a kernel-internal socket entry in /proc/net/tcp
    // that has no owning process fd, so matching by local_port alone fails.
    // Instead, match by the original destination (orig_dst): the client's real
    // socket has remote=orig_dst, and we find it by scanning process fds.
    let pid = match find_pid_by_orig_dst(orig_dst, peer_ip) {
        Some(p) => p,
        None => return (None, None, None, None, None),
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
/// Matches the client-side socket whose local port = peer_port.
/// The client connected to :443, but iptables REDIRECT rewrote the destination
/// to 127.0.0.1:8444. So the client socket in /proc/net/tcp shows:
///   client_ip:peer_port -> 127.0.0.1:8444
/// Convert an IP address to the hex format used in /proc/net/tcp.
/// IPv4: "0100007F" (little-endian bytes)
/// IPv6: 16 bytes in mixed endian (4 little-endian 32-bit words)
fn ip_to_hex(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!("{:02X}{:02X}{:02X}{:02X}", octets[3], octets[2], octets[1], octets[0])
        }
        IpAddr::V6(v6) => {
            // /proc/net/tcp6 uses 4 32-bit words in little-endian
            let octets = v6.octets();
            let mut words = Vec::new();
            for i in (0..16).step_by(4) {
                words.push(format!("{:02X}{:02X}{:02X}{:02X}", octets[i+3], octets[i+2], octets[i+1], octets[i]));
            }
            words.join("")
        }
    }
}

/// Find which PID owns a socket connected to orig_dst from peer_ip.
/// Scans /proc/net/tcp for ESTABLISHED entries where remote=orig_dst and local_ip=peer_ip,
/// collects the inodes, then scans /proc/*/fd to find the owning PID.
fn find_pid_by_orig_dst(orig_dst: SocketAddr, peer_ip: IpAddr) -> Option<i32> {
    let remote_ip_hex = ip_to_hex(orig_dst.ip());
    let remote_port_hex = format!("{:04X}", orig_dst.port());
    let local_ip_hex = ip_to_hex(peer_ip);
    let remote_addr = format!("{}:{}", remote_ip_hex, remote_port_hex);

    // Collect inodes from /proc/net/tcp where remote=orig_dst, local_ip=peer_ip, ESTABLISHED.
    let mut target_inodes = HashSet::new();
    for proc_file in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = fs::read_to_string(proc_file) {
            for (i, line) in content.lines().enumerate() {
                if i == 0 {
                    continue;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 10 {
                    continue;
                }
                if parts[3] != "01" {
                    continue; // not ESTABLISHED
                }
                let local = parts[1];
                let remote = parts[2];
                // Match remote == orig_dst and local_ip == peer_ip
                if remote.eq_ignore_ascii_case(&remote_addr)
                    && local.split(':').next().map(|s| s.eq_ignore_ascii_case(&local_ip_hex)).unwrap_or(false)
                {
                    target_inodes.insert(parts[9].to_string());
                }
            }
        }
    }

    if target_inodes.is_empty() {
        return None;
    }

    // Scan /proc/*/fd for any process that owns one of these inodes.
    // Note: readlink on /proc/<pid>/fd/<n> requires ptrace_may_access, which
    // checks that caller gid == target gid. The proxy must run with the same
    // effective GID as the target processes (i.e., NOT via sg agwproxy).
    let my_pid = std::process::id() as i32;
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let name = entry.file_name();
        let pid: i32 = match name.to_string_lossy().parse() {
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
                    let link_str = link.to_string_lossy();
                    if let Some(inode) = link_str.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                        if target_inodes.contains(inode) {
                            return Some(pid);
                        }
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
