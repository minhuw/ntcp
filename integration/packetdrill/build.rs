use std::{env, path::PathBuf, process::Command};
fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    assert!(
        Command::new("cc")
            .args([
                "-std=gnu11",
                "-fPIC",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wno-unused-parameter",
                "-c",
                "shim.c",
                "-o"
            ])
            .arg(out.join("shim.o"))
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("ar")
            .arg("crs")
            .arg(out.join("libshim.a"))
            .arg(out.join("shim.o"))
            .status()
            .unwrap()
            .success()
    );
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=shim");
    println!("cargo:rerun-if-changed=shim.c");
    println!("cargo:rerun-if-changed=packetdrill.h");
}
