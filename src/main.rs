extern crate nix;
extern crate failure;
extern crate futures;
extern crate tokio_core;
extern crate tokio_io;
extern crate bytes;
extern crate trust_dns_resolver;
#[macro_use] extern crate log;
extern crate env_logger;

use failure::Error;
use tokio_core::reactor;
use tokio_core::reactor::Timeout;
use tokio_core::net::TcpStream;
use std::time::Duration;
use std::net::SocketAddr;
use futures::future::{self, Either};
use futures::{Future, Stream};
use std::io;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::io::{read_to_end, write_all};
use std::io::Write;
use tokio_io::codec::BytesCodec;



const LIFELINE1_SERVERS : [&'static str;2] = [
    "lifeline.exys.org",
    "lifeline.superscale.io"
];


fn local(handle: reactor::Handle, remote_r: Box<Stream<Item = bytes::Bytes, Error = io::Error>> )
    -> Box<Stream<Item = bytes::BytesMut, Error = io::Error>> {

    let timeout = Timeout::new(Duration::from_millis(1000), &handle).unwrap();
    let addr    = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127,0,0,1)), 1234);
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

    Box::new(tcp.map(move |stream| {
        info!("have local connection");
        //let stream = CloseWithShutdown(stream);
        let (local_w, local_r) = stream.framed(BytesCodec::new()).split();
        let copy = remote_r.forward(local_w)
            .then(|result| {
                if let Err(e) = result {
                    panic!("failed to write to socket: {}", e)
                }
                Ok(())
            });
        handle.spawn(copy);
        local_r
    }).flatten_stream())
}




fn build_helo(remotename: &str) -> Result<String, Error>
{
    use nix::unistd;
    let mut buf = [0u8; 64];
    let hostname_cstr = unistd::gethostname(&mut buf)?;
    let hostname = hostname_cstr.to_str()?;

    Ok(format!("GET /lifeline/1 HTTP/1.1\r\n\
            Host: {}\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\
            User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.63 Safari/537.36\r\n\
            Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n\
            Sec-WebSocket-Protocol: chat, superchat\r\n\
            Sec-WebSocket-Version: 13\r\n\
            X-LF-Name: {}\r\n\
            \r\n",
            remotename,
            hostname))
}


fn remote(hostname : &str, ip: std::net::IpAddr) -> Result<(), Error> {

    let addr = SocketAddr::new(ip, 80);
    info!("connecting to {} at {}", hostname, addr);

    let helo = build_helo(hostname)?;
    let mut core = reactor::Core::new()?;
    let handle  = core.handle();
    let handle2 = handle.clone();

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
        .map_err(|e| error!("Error: {}", e))
        .and_then(move |mut stream| {
            info!("bearer connected");

            match stream.write(&helo.as_bytes()) {
                Ok(_)  => {},
                Err(_) => return Box::new(future::err(())) as  Box<Future<Item=(), Error=()>>,
            };

            Box::new(tokio_io::io::read(stream, vec![0; 1024])
                .and_then(|(socket, _b, _size)| {
                    // we're ignoring the content. this is ok because lifeline v1 is dead code
                    // anyway. the header is fixed size and fits in a single package.
                    info!("icoming control connection");

                    let (remote_w, remote_r) = socket.framed(BytesCodec::new()).split();

                    let remote_r = remote_r.map(|b|b.freeze());
                    let local_r = local(handle2, Box::new(remote_r));
                    let local_r = local_r.map(|b|b.freeze());

                    local_r.forward(remote_w)
                        .then(|result| {
                            if let Err(e) = result {
                                panic!("failed to write to socket: {}", e)
                            }
                            Ok(())
                        })
                        //future::ok::<(), std::io::Error>(())
                })
                .map_err(|_|()))
        });

    core.run(tcp).ok();

    Ok(())
}

fn resolve(name: &str) -> Result<(Vec<std::net::IpAddr>), Error> {
    info!("resolving {}", name);

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
        socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        protocol: Protocol::Udp
    });
    config.add_name_server(NameServerConfig{
        socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 53),
        protocol: Protocol::Udp
    });
    config.add_name_server(NameServerConfig{
        socket_addr: SocketAddr::new(
                         IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,)),53),
                         protocol: Protocol::Udp,
    });

    // google
    config.add_name_server(NameServerConfig{
        socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        protocol: Protocol::Udp
    });
    config.add_name_server(NameServerConfig{
        socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53),
        protocol: Protocol::Udp
    });
    config.add_name_server(NameServerConfig{
        socket_addr: SocketAddr::new(
                         IpAddr::V6(Ipv6Addr::new(0x2001,0x4860,0x4860,0,0,0,0,0x8888,)),53),
                         protocol: Protocol::Udp,
    });

    // from local dhcp as fallback, if all others are blocked
    if let Ok((sysconf, _))  = system_conf::read_system_conf() {
        for ns in sysconf.name_servers() {
            config.add_name_server(*ns);
        }
    }

    let resolver = Resolver::new(config, ResolverOpts::default())?;

    let response = match resolver.lookup_ip(name) {
        Ok(r) => r,
        Err(e) => return Err(failure::Error::from(std::io::Error::new(std::io::ErrorKind::Other, e.description()))),
    };

    Ok(response.iter().collect())
}


fn main() {
    use std::env;
    if let Err(_) = env::var("RUST_LOG") {
        env::set_var("RUST_LOG", "hatch=debug");
    }
    env_logger::init();

    let mut ips : Vec<(&'static str, std::net::IpAddr)> = Vec::new();
    for name in LIFELINE1_SERVERS.iter() {
        if let Ok(mut rips) = resolve(name) {
            for ip in rips {
                ips.push((name,ip));
            }
        }
    }

    for ip in ips {
        remote(ip.0, ip.1).unwrap();
    }
}

