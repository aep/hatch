extern crate failure;
extern crate futures;
#[macro_use]  extern crate tokio_core;
extern crate tokio_io;
extern crate bytes;
extern crate trust_dns_resolver;
#[macro_use] extern crate log;
extern crate env_logger;
extern crate tokio_timer;
extern crate nix;
extern crate mtdparts;
extern crate ed25519_dalek;
extern crate bs58;
extern crate sha2;
extern crate libc;

mod services;
use std::thread;
use std::fs::File;
use std::io::Read;
use ed25519_dalek::{SecretKey, PublicKey};

fn getidentity() -> Option<String> {
    let f = match File::open("/proc/mtd") {
        Ok(f) => f,
        Err(e) => {warn!("cannot read /proc/mtd: {}", e); return None;},
    };
    let parts = match mtdparts::parse_mtd(&f) {
        Ok(v) => v,
        Err(e) => {warn!("cannot parse /proc/mtd: {}", e); return None;},
    };
    let i = match parts.get("identity") {
        Some(i) => i,
        None  => {warn!("missing mtd partition 'identity'"); return None;},
    };
    let mut f = match File::open(format!("/dev/mtdblock{}", i)) {
        Ok(f) => f,
        Err(e) => {warn!("cannot open /dev/mtdblock{}: {}", i, e); return None;},
    };

    let mut buf = [0;4096];
    if let Err(e) = f.read_exact(&mut buf) {
        warn!("cannot read /dev/mtdblock{}: {}", i, e);
        return None;
    }

    let sc :SecretKey = match SecretKey::from_bytes(&buf[..32]) {
        Ok(v) => v,
        Err(e) => {warn!("cannot load secret data: {}", e); return None;},
    };

    let pk: PublicKey = PublicKey::from_secret::<sha2::Sha512>(&sc);

    Some(bs58::encode(pk.as_bytes())
        .with_alphabet(bs58::alphabet::BITCOIN)
        .into_string())

}

fn main() {
    use std::env;
    if let Err(_) = env::var("RUST_LOG") {
        env::set_var("RUST_LOG", "hatch=info");
    }
    env_logger::init();

    let identity = match getidentity() {
        Some(id) => id,
        None => {
            use nix::unistd;
            let mut buf = [0u8; 64];
            let hostname_cstr = unistd::gethostname(&mut buf).unwrap();
            hostname_cstr.to_str().unwrap().to_string()
        }
    };


    info!("using identity: {}", identity);


    let t1 = thread::spawn(move || {
        services::lifeline1::main(identity);
    });

    t1.join().unwrap();
}
