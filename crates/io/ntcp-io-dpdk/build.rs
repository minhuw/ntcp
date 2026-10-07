fn main() {
    println!("cargo:rerun-if-changed=src/shim.c");
    println!("cargo:rerun-if-changed=src/shim.h");
    #[cfg(feature = "native")]
    native();
}

#[cfg(feature = "native")]
fn native() {
    use std::{collections::HashSet, env};
    assert_eq!(
        env::var("HOST").unwrap(),
        env::var("TARGET").unwrap(),
        "ntcp-io-dpdk native: cross compilation is not supported by this build script"
    );
    let static_link = env::var_os("CARGO_FEATURE_STATIC").is_some();
    let sdk = pkg_config::Config::new()
        .statik(static_link)
        .cargo_metadata(false)
        .probe("libdpdk")
        .unwrap_or_else(|e| panic!("ntcp-io-dpdk native requires the DPDK SDK, pkg-config libdpdk, and a C compiler. Set PKG_CONFIG_PATH for your SDK. No stub backend is built: {e}"));
    // Keep SDK-specific flags, including -include rte_config.h and -march.
    let output =
        pkg_config_cflags(static_link).expect("ntcp-io-dpdk native: cannot run pkg-config");
    assert!(
        output.status.success(),
        "ntcp-io-dpdk native: pkg-config --cflags failed"
    );
    let flags = shlex::split(std::str::from_utf8(&output.stdout).unwrap())
        .expect("ntcp-io-dpdk native: invalid quoted pkg-config flags");
    cc::Build::new()
        .file("src/shim.c")
        .flags(&flags)
        .flag_if_supported("-std=gnu11")
        .warnings(true)
        .compile("ntcp_dpdk_shim");
    #[cfg(feature = "test-pmd")]
    {
        println!("cargo:rerun-if-changed=tests/ring_fixture.c");
        cc::Build::new()
            .file("tests/ring_fixture.c")
            .flags(&flags)
            .flag_if_supported("-std=gnu11")
            .compile("ntcp_dpdk_test_fixture");
        if !static_link {
            println!("cargo:rustc-link-lib=rte_net_ring");
        }
    }
    for path in &sdk.link_paths {
        println!("cargo:rustc-link-search=native={}", path.display());
    }
    // libdpdk --static uses -l:librte_*.a inside whole-archive. Encode this
    // as Rust link-library modifiers so registration survives downstream links;
    // rustc-link-arg alone would only affect this crate's executables.
    let archives: HashSet<_> = sdk
        .libs
        .iter()
        .filter_map(|lib| lib.strip_prefix(":lib").and_then(|s| s.strip_suffix(".a")))
        .collect();
    let mut emitted = HashSet::new();
    for lib in &sdk.libs {
        let (name, whole) = match lib.strip_prefix(":lib").and_then(|s| s.strip_suffix(".a")) {
            Some(name) => (name, true),
            None if archives.contains(lib.as_str()) => continue,
            None => (lib.as_str(), static_link && lib.starts_with("rte_")),
        };
        assert!(
            !name.starts_with(':'),
            "unsupported DPDK library flag: {lib}"
        );
        if emitted.insert(name) {
            if whole {
                println!("cargo:rustc-link-lib=static:+whole-archive={name}");
            } else {
                println!("cargo:rustc-link-lib={name}");
            }
        }
    }
    for args in sdk.ld_args {
        if !args
            .iter()
            .any(|s| matches!(s.as_str(), "--whole-archive" | "--no-whole-archive"))
        {
            println!("cargo:rustc-link-arg=-Wl,{}", args.join(","));
        }
    }
}

// pkg-config's command/resolver is private. Match its scoped-variable precedence
// and default-executable fallback for the raw flags it does not expose in Library.
#[cfg(feature = "native")]
fn pkg_config_env(base: &str) -> Option<std::ffi::OsString> {
    use std::env;
    let target = env::var("TARGET").unwrap();
    let kind = if env::var("HOST").unwrap() == target {
        "HOST"
    } else {
        "TARGET"
    };
    [
        format!("{base}_{target}"),
        format!("{base}_{}", target.replace('-', "_")),
        format!("{kind}_{base}"),
        base.to_owned(),
    ]
    .into_iter()
    .find_map(|name| {
        println!("cargo:rerun-if-env-changed={name}");
        env::var_os(name)
    })
}

#[cfg(feature = "native")]
fn pkg_config_cflags(static_link: bool) -> std::io::Result<std::process::Output> {
    use std::process::Command;
    let exe = pkg_config_env("PKG_CONFIG");
    let run = |exe: &std::ffi::OsStr| {
        let mut cmd = Command::new(exe);
        if static_link {
            cmd.arg("--static");
        }
        cmd.args(["--cflags", "libdpdk"]);
        for base in [
            "PKG_CONFIG_PATH",
            "PKG_CONFIG_LIBDIR",
            "PKG_CONFIG_SYSROOT_DIR",
        ] {
            if let Some(value) = pkg_config_env(base) {
                cmd.env(base, value);
            }
        }
        cmd.env("PKG_CONFIG_ALLOW_SYSTEM_LIBS", "1")
            .env("PKG_CONFIG_ALLOW_SYSTEM_CFLAGS", "1")
            .output()
    };
    run(exe
        .as_deref()
        .unwrap_or_else(|| std::ffi::OsStr::new("pkg-config")))
    .or_else(|error| {
        if exe.is_none() {
            run(std::ffi::OsStr::new("pkgconf"))
        } else {
            Err(error)
        }
    })
}
