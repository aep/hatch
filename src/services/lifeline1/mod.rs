use failure::{self, Error};
use tokio_core::reactor;
use tokio_core::reactor::Timeout;
use tokio_core::net::TcpStream;
use std::time::Duration;
use std::net::SocketAddr;
use futures::future::{self, Either};
use futures::{Future};
use tokio_io::{self, AsyncRead, AsyncWrite};
use std::io::Write;
use std::{thread};
use std::os::unix::io::AsRawFd;
use nix::sys::socket::{setsockopt, sockopt};
use std;
use libc;

mod copy;

const LIFELINE1_SERVERS : [&'static str;3] = [
    "lifeline.hy5.berlin",
    "lifeline.exys.org",
    "lifeline.superscale.io"
];

fn local(handle: reactor::Handle) -> Box<Future<Item=(Box<AsyncRead>, Box<AsyncWrite>), Error=std::io::Error>> {
    let timeout = Timeout::new(Duration::from_millis(1000), &handle).unwrap();
    let addr    = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127,0,0,1)), 22);
    let tcp     = TcpStream::connect(&addr, &handle);

    let tcp = tcp.select2(timeout).then(|res| match res {
        Ok(Either::A((got, _timeout))) => Ok(got),
        Ok(Either::B((_timeout_error, _get))) => {
            Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Client timed out while connecting",
                    ))
        }
        Err(Either::A((get_error, _timeout))) => Err(get_error),
        Err(Either::B((timeout_error, _get))) => Err(From::from(timeout_error)),
    });

    Box::new(tcp.and_then(move |stream| {
        info!("local ssh connected");
        let (local_r, local_w) = stream.split();
        future::ok((Box::new(local_r) as Box<AsyncRead>,
                    Box::new(local_w) as Box<AsyncWrite>))
    }))
}

fn build_helo(identity: &str, remotename: &str) -> Result<String, Error>
{
    Ok(format!("GET /lifeline/1 HTTP/1.1\r\n\
            Host: {}\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\
            User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.63 Safari/537.36\r\n\
            Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n\
            Sec-WebSocket-Protocol: chat, superchat\r\n\
            Sec-WebSocket-Version: 13\r\n\
            X-LF-Name: hatch.{}\r\n\
            \r\n",
            remotename,
            identity))
}

fn remote(identity: &str, hostname : &str, ip: std::net::IpAddr) -> Result<(), Error> {

    let addr = SocketAddr::new(ip, 80);
    info!("connecting to {} at {}", hostname, addr);

    let helo = build_helo(identity, hostname)?;
    let mut core = reactor::Core::new()?;
    let handle  = core.handle();
    let handle2 = handle.clone();
    let handle3 = handle.clone();
    let handle4 = handle.clone();

    let timeout = Timeout::new(Duration::from_millis(1000), &handle)?;
    let tcp     = TcpStream::connect(&addr, &handle);

    let tcp = tcp.select2(timeout).then(|res| match res {
        Ok(Either::A((got, _timeout))) => Ok(got),
        Ok(Either::B((_timeout_error, _get))) => {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Client timed out while connecting",
            ))
        }
        Err(Either::A((get_error, _timeout))) => Err(get_error),
        Err(Either::B((timeout_error, _get))) => Err(From::from(timeout_error)),
    });

    let tcp = tcp
        .map_err(|e| warn!("Error: {}", e))
        .and_then(move |mut stream| {
            info!("bearer connected");

            let fd = stream.as_raw_fd();
            setsockopt(fd, sockopt::KeepAlive,    &true).ok();
            setsockopt(fd, sockopt::TcpKeepIdle,  &10).ok();

            unsafe{libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, &10 as *const i32 as *const libc::c_void, 4);}
            unsafe{libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, &10 as *const i32  as *const libc::c_void, 4);}

            match stream.write(&helo.as_bytes()) {
                Ok(_)  => {},
                Err(_) => return Box::new(future::err(())) as  Box<Future<Item=(), Error=()>>,
            };

            // additional timeout for 3 hours. this is done because i don't trust SO_KEEPALIVE
            let timeout = Timeout::new(Duration::from_secs(7800), &handle).unwrap();

            Box::new(tokio_io::io::read(stream, vec![0; 1024])
                .select2(timeout).then(|res| match res {
                    Ok(Either::A((got, _timeout))) => Ok(got),
                    Ok(Either::B((_timeout_error, _get))) => {
                        Err(std::io::Error::new(std::io::ErrorKind::TimedOut,"safety reset",))
                    },
                    Err(Either::A((get_error, _timeout))) => Err(get_error),
                    Err(Either::B((timeout_error, _get))) => Err(From::from(timeout_error)),
                })
                .and_then(|(socket, _b, _size)| {
                    // we're ignoring the content. this is ok because lifeline v1 is dead code
                    // anyway. the header is fixed size and fits in a single package.
                    info!("icoming control connection");

                    let (remote_r, remote_w) = socket.split();
                    local(handle2).and_then(|(local_r, local_w)|{
                        let copy1 = copy::copy_with_deadline(remote_r, local_w, handle3, Duration::from_secs(60));
                        let copy2 = copy::copy_with_deadline(local_r, remote_w, handle4, Duration::from_secs(60));
                        copy1.select2(copy2).then(|_| {
                            info!("stream ended");
                            future::ok::<(), std::io::Error>(())
                        })
                    })
                })
                .map_err(|e|warn!("{:?}",e)))
        });

    core.run(tcp).ok();

    Ok(())
}

fn resolve(name: &str) -> Result<(Vec<std::net::IpAddr>), Error> {
    debug!("resolving {}", name);

    use std::net::*;
    use trust_dns_resolver::{
        Resolver,
        system_conf,
    };
    use trust_dns_resolver::config::*;

    let mut config = ResolverConfig::new();
    use std::error::Error;

    // cloudflare
    config.add_name_server(NameServerConfig{
        tls_dns_name: None,
        socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        protocol: Protocol::Udp,
    });
    config.add_name_server(NameServerConfig{
        tls_dns_name: None,
        socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 53),
        protocol: Protocol::Udp
    });
    config.add_name_server(NameServerConfig{
        tls_dns_name: None,
        socket_addr: SocketAddr::new(
                         IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,)),53),
                         protocol: Protocol::Udp,
    });

    // google
    config.add_name_server(NameServerConfig{
        tls_dns_name: None,
        socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        protocol: Protocol::Udp
    });
    config.add_name_server(NameServerConfig{
        tls_dns_name: None,
        socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53),
        protocol: Protocol::Udp
    });
    config.add_name_server(NameServerConfig{
        tls_dns_name: None,
        socket_addr: SocketAddr::new(
                         IpAddr::V6(Ipv6Addr::new(0x2001,0x4860,0x4860,0,0,0,0,0x8888,)),53),
                         protocol: Protocol::Udp,
    });

    // from local dhcp as fallback, if all others are blocked
    if let Ok((sysconf, _))  = system_conf::read_system_conf() {
        for ns in sysconf.name_servers() {
            config.add_name_server(ns.clone());
        }
    }

    let resolver = Resolver::new(config, ResolverOpts::default())?;

    let response = match resolver.lookup_ip(name) {
        Ok(r) => r,
        Err(e) => return Err(failure::Error::from(std::io::Error::new(std::io::ErrorKind::Other, e.description()))),
    };

    Ok(response.iter().collect())
}

pub fn main(identity: String) {
    loop {
        let mut ips : Vec<(&'static str, std::net::IpAddr)> = Vec::new();
        for name in LIFELINE1_SERVERS.iter() {
            if let Ok(mut rips) = resolve(name) {
                for ip in rips {
                    ips.push((name,ip));
                }
            }
        }

        for ip in ips {
            if let Err(e) = remote(&identity, ip.0, ip.1) {
                warn!("{}", e);
            }
        }

        thread::sleep(Duration::from_secs(1));
    }
}

