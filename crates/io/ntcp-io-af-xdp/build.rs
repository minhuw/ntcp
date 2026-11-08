fn main() {
    println!("cargo:rerun-if-changed=src/steer.bpf.c");
    #[cfg(feature = "host")]
    host();
}

// The host feature embeds the XDP program, compiled here for the BPF target,
// and links libbpf, which loads it. NTCP_BPF_CLANG names a clang with the BPF
// backend (default `clang`); it must not be a wrapper that adds host-target
// flags, such as nix's cc-wrapper: use nix's clang-unwrapped. NTCP_BPF_CFLAGS
// adds flags, such as the include directory of Linux UAPI headers when the
// compiler does not search it (nix's linuxHeaders, or the multiarch directory
// that holds <asm/types.h> on Debian-like systems). libbpf's own include
// directories come from pkg-config.
#[cfg(feature = "host")]
fn host() {
    use std::{env, path::PathBuf, process::Command};
    assert_eq!(
        env::var("CARGO_CFG_TARGET_OS").unwrap(),
        "linux",
        "ntcp-io-af-xdp host: AF_XDP and XDP exist on Linux only"
    );
    let libbpf = pkg_config::Config::new()
        .atleast_version("1.0")
        .probe("libbpf")
        .unwrap_or_else(|e| {
            panic!("ntcp-io-af-xdp host requires libbpf >= 1.0 found by pkg-config: {e}")
        });
    for name in ["NTCP_BPF_CLANG", "NTCP_BPF_CFLAGS"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let clang = env::var_os("NTCP_BPF_CLANG").unwrap_or_else(|| "clang".into());
    let extra = env::var("NTCP_BPF_CFLAGS").unwrap_or_default();
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("steer.bpf.o");
    let mut command = Command::new(&clang);
    command.args(["-target", "bpf", "-O2", "-g", "-Wall", "-Werror", "-c"]);
    for path in &libbpf.include_paths {
        command.arg("-I").arg(path);
    }
    command
        .args(extra.split_whitespace())
        .arg("src/steer.bpf.c")
        .arg("-o")
        .arg(&output);
    let status = command.status().unwrap_or_else(|e| {
        panic!("ntcp-io-af-xdp host: cannot run {clang:?} (set NTCP_BPF_CLANG): {e}")
    });
    assert!(
        status.success(),
        "ntcp-io-af-xdp host: compiling src/steer.bpf.c for the BPF target failed"
    );
}
