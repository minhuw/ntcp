use std::{env, path::PathBuf, process::Command};
fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    // Only shim is linked into the plugin; the unit tests link abi_selfcheck through #[link].
    for name in ["shim", "abi_selfcheck"] {
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
                ])
                .arg(format!("{name}.c"))
                .arg("-o")
                .arg(out.join(format!("{name}.o")))
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("ar")
                .arg("crs")
                .arg(out.join(format!("lib{name}.a")))
                .arg(out.join(format!("{name}.o")))
                .status()
                .unwrap()
                .success()
        );
    }
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=shim");
    println!("cargo:rerun-if-changed=shim.c");
    println!("cargo:rerun-if-changed=abi_selfcheck.c");
    println!("cargo:rerun-if-changed=packetdrill.h");
    println!("cargo:rerun-if-changed=../../crates/adapters/ntcp-socket/src/boundary.h");
}
