// SPDX-License-Identifier: Apache-2.0
// Transparent proxy core: accept REDIRECTed connections, retrieve original
// destination via SO_ORIGINAL_DST, then MITM TLS or blind-tunnel.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::tls::Certifier;
use crate::http_mitm::UpstreamConnector;
use crate::detect;
use crate::audit;
use crate::attribution;

/// Handle a single incoming connection from the transparent proxy listener.
pub async fn handle_connection(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    certifier: Arc<Certifier>,
    connector: Arc<UpstreamConnector>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Get original destination via SO_ORIGINAL_DST
    let orig_dst = get_original_dst(&client)?;

    // Connect to upstream
    let upstream = connector.connect_tcp(orig_dst).await?;

    // Peek first bytes to detect TLS ClientHello
    let mut peek_buf = [0u8; 1];
    let n = client.peek(&mut peek_buf).await?;

    if n > 0 && peek_buf[0] == 0x16 {
        // TLS handshake — MITM
        handle_tls_mitm(client, orig_dst, peer_addr, certifier, connector).await
    } else {
        // Non-TLS — blind tunnel
        blind_tunnel(client, upstream).await
    }
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut cr, mut cw) = client.split();
    let (mut ur, mut uw) = upstream.split();

    tokio::try_join!(
        tokio::io::copy(&mut cr, &mut uw),
        tokio::io::copy(&mut ur, &mut cw),
    )?;

    Ok(())
}

/// TLS MITM: terminate TLS with a dynamic cert, inspect HTTP, forward to upstream over TLS.
async fn handle_tls_mitm(
    client: TcpStream,
    orig_dst: SocketAddr,
    peer_addr: SocketAddr,
    certifier: Arc<Certifier>,
    connector: Arc<UpstreamConnector>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Extract hostname from original destination
    let hostname = orig_dst.ip().to_string();

    // Accept TLS from client with a cert signed by our CA
    let server_config = certifier.server_config(&hostname)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config);

    let mut tls_client = acceptor.accept(client).await?;

    // Connect to upstream over TLS
    let upstream_tls = connector.connect_tls(orig_dst).await?;

    // Process HTTP over the TLS connection
    crate::http_mitm::process_http(
        &mut tls_client,
        upstream_tls,
        orig_dst,
        peer_addr,
    ).await
}
