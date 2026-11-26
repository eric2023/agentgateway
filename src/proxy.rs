// SPDX-License-Identifier: Apache-2.0
// Transparent proxy core: accept REDIRECTed connections, retrieve original
// destination via SO_ORIGINAL_DST, then MITM TLS or blind-tunnel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::tls::Certifier;
use crate::http_mitm::UpstreamConnector;
use crate::detect;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Handle a single incoming connection from the transparent proxy listener.
pub async fn handle_connection(
    client: TcpStream,
    peer_addr: SocketAddr,
    certifier: Arc<Certifier>,
    connector: Arc<UpstreamConnector>,
) -> Result<(), BoxError> {
    // Get original destination via SO_ORIGINAL_DST
    let orig_dst = get_original_dst(&client)?;

    // Peek first bytes to detect TLS ClientHello
    let mut peek_buf = [0u8; 16384]; // TLS record max = 16384 (was 1024, truncated extended ClientHello)
    let n = match tokio::time::timeout(
        Duration::from_secs(30),
        client.peek(&mut peek_buf),
    ).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => {
            // Timeout or no data — try blind tunnel to orig_dst
            let upstream = connector.connect_tcp(orig_dst).await?;
            return blind_tunnel(client, upstream).await;
        }
    };

    if peek_buf[0] == 0x16 {
        // TLS handshake — extract SNI from peeked ClientHello
        let sni = extract_sni(&peek_buf[..n]);

        // Only MITM AI hosts; blind-tunnel everything else
        let should_mitm = sni.as_deref()
            .map(detect::should_mitm_host)
            .unwrap_or(false);

        if should_mitm {
            handle_tls_mitm(client, orig_dst, peer_addr, certifier, connector, sni.as_deref()).await
        } else {
            // Non-AI host — blind tunnel (peeked bytes still in TCP buffer)
            let upstream = connector.connect_tcp(orig_dst).await?;
            blind_tunnel(client, upstream).await
        }
    } else {
        // Non-TLS — blind tunnel
        let upstream = connector.connect_tcp(orig_dst).await?;
        blind_tunnel(client, upstream).await
    }
}

/// Extract SNI hostname from a raw TLS ClientHello record.
/// Returns None if the ClientHello is truncated or has no SNI extension.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    // TLS record header: type(1) + version(2) + length(2) = 5 bytes
    if data.len() < 5 || data[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let record = data.get(5..5 + record_len)?;

    // Handshake header: type(1) + length(3) = 4 bytes
    if record.len() < 4 || record[0] != 0x01 {
        return None;
    }
    let hs_len = ((record[1] as usize) << 16)
        | ((record[2] as usize) << 8)
        | (record[3] as usize);
    let hello = record.get(4..4 + hs_len)?;

    // ClientHello body:
    //   protocol_version(2) + random(32) + session_id_len(1) + session_id(var)
    let mut pos = 2 + 32; // skip version + random
    if pos >= hello.len() {
        return None;
    }
    let sid_len = hello[pos] as usize;
    pos += 1 + sid_len;

    // cipher_suites_len(2) + cipher_suites(var)
    if pos + 2 > hello.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // compression_methods_len(1) + compression_methods(var)
    if pos >= hello.len() {
        return None;
    }
    let cm_len = hello[pos] as usize;
    pos += 1 + cm_len;

    // extensions_len(2) + extensions(var)
    if pos + 2 > hello.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;
    let extensions = hello.get(pos..pos + ext_len)?;

    // Parse extensions to find SNI (type 0x0000)
    let mut epos = 0;
    while epos + 4 <= extensions.len() {
        let ext_type = u16::from_be_bytes([extensions[epos], extensions[epos + 1]]);
        let ext_data_len = u16::from_be_bytes([extensions[epos + 2], extensions[epos + 3]]) as usize;
        epos += 4;
        if epos + ext_data_len > extensions.len() {
            break;
        }
        let ext_data = &extensions[epos..epos + ext_data_len];
        epos += ext_data_len;

        if ext_type == 0x0000 && ext_data.len() >= 5 {
            // SNI extension:
            //   server_name_list_len(2) + name_type(1) + name_len(2) + name(var)
            let _list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]);
            if ext_data[2] != 0x00 {
                continue; // not host_name type
            }
            let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
            if ext_data.len() >= 5 + name_len {
                return std::str::from_utf8(&ext_data[5..5 + name_len])
                    .ok()
                    .map(|s| s.to_string());
            }
        }
    }

    None
}

/// Get the original destination address via SO_ORIGINAL_DST socket option.
fn get_original_dst(sock: &TcpStream) -> Result<SocketAddr, std::io::Error> {
    use std::os::unix::io::AsRawFd;
    let fd = sock.as_raw_fd();

    let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut addr_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr_storage as *mut _ as *mut libc::c_void,
            &mut addr_len,
        )
    };

    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Parse as sockaddr_in or sockaddr_in6
    let family = addr_storage.ss_family as libc::c_int;
    match family {
        libc::AF_INET => {
            let addr_in: libc::sockaddr_in = unsafe { std::mem::transmute_copy(&addr_storage) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr));
            let port = u16::from_be(addr_in.sin_port);
            Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port))
        }
        libc::AF_INET6 => {
            let addr_in6: libc::sockaddr_in6 = unsafe { std::mem::transmute_copy(&addr_storage) };
            let ip = std::net::Ipv6Addr::from(addr_in6.sin6_addr.s6_addr);
            let port = u16::from_be(addr_in6.sin6_port);
            Ok(SocketAddr::new(std::net::IpAddr::V6(ip), port))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown address family: {}", family),
        )),
    }
}

/// Blind TCP tunnel — no inspection, just pipe bytes both ways.
async fn blind_tunnel(
    mut client: TcpStream,
    mut upstream: TcpStream,
) -> Result<(), BoxError> {
    let (mut cr, mut cw) = client.split();
    let (mut ur, mut uw) = upstream.split();

    let client_to_upstream = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = tokio::time::timeout(
                Duration::from_secs(300),
                cr.read(&mut buf),
            ).await
            .map_err(|_| -> BoxError { "blind tunnel idle timeout (client→upstream)".into() })??;
            if n == 0 { return Ok::<(), BoxError>(()); }
            uw.write_all(&buf[..n]).await?;
            uw.flush().await?;
        }
    };

    let upstream_to_client = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = tokio::time::timeout(
                Duration::from_secs(300),
                ur.read(&mut buf),
            ).await
            .map_err(|_| -> BoxError { "blind tunnel idle timeout (upstream→client)".into() })??;
            if n == 0 { return Ok::<(), BoxError>(()); }
            cw.write_all(&buf[..n]).await?;
            cw.flush().await?;
        }
    };

    tokio::try_join!(client_to_upstream, upstream_to_client)?;
    Ok(())
}

/// TLS MITM: terminate TLS with a dynamic cert, inspect HTTP, forward to upstream over TLS.
async fn handle_tls_mitm(
    client: TcpStream,
    orig_dst: SocketAddr,
    peer_addr: SocketAddr,
    certifier: Arc<Certifier>,
    connector: Arc<UpstreamConnector>,
    sni: Option<&str>,
) -> Result<(), BoxError> {
    // Use SNI hostname for certificate generation (fallback to IP if no SNI)
    let hostname_owned;
    let hostname: &str = match sni {
        Some(h) => h,
        None => {
            hostname_owned = orig_dst.ip().to_string();
            &hostname_owned
        }
    };

    // Accept TLS from client with a cert signed by our CA
    let server_config = certifier.server_config(hostname)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config);

    let mut tls_client = tokio::time::timeout(
        Duration::from_secs(10),
        acceptor.accept(client),
    )
    .await
    .map_err(|_| -> BoxError { "TLS handshake timeout (client)".into() })??;

    // Connect to upstream over TLS, using SNI as ServerName
    let upstream_tls = connector.connect_tls(orig_dst, sni).await?;

    // Process HTTP over the TLS connection
    crate::http_mitm::process_http(
        &mut tls_client,
        upstream_tls,
        orig_dst,
        peer_addr,
        sni,
    ).await
}
