use std::{env, path::PathBuf};

const SRC: &str = "./src/bpf/backdoor.bpf.c";
fn main() {
    // normal OUT_DIR approach doesn't work (https://github.com/rust-lang/rust/issues/66920)
    // let skel = PathBuf::from(env::var("OUT_DIR").unwrap()).join("backdoor.skel.rs");
    let skel = PathBuf::from(env::var("OUT_DIR").unwrap());
    let mut skel = skel.as_path();
    let skel = loop {
        if skel.ends_with("target") {
            break skel;
        }
        skel = skel.parent().unwrap();
    }
    .join("backdoor.skel.rs");
    println!("cargo:rerun-if-changed={}", SRC);
    if let Err(e) = libbpf_cargo::SkeletonBuilder::new(SRC)
        .debug(true)
        .clang_args("-Wall -Werror")
        .generate(skel)
    {
        match e {
            libbpf_cargo::Error::Build(e) => panic!("Build error: {}", e),
            libbpf_cargo::Error::Generate(e) => panic!("Generation error: {}", e),
        }
    }
}
