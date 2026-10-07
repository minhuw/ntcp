fn main() {
    println!("cargo:rerun-if-changed=src/variadic.c");
    println!("cargo:rerun-if-changed=src/boundary.c");
    println!("cargo:rerun-if-changed=src/stdio.c");
    println!("cargo:rustc-link-lib=dl");
    cc::Build::new()
        .file("src/variadic.c")
        .file("src/boundary.c")
        .file("src/stdio.c")
        .flag("-fexceptions")
        .compile("ntcp_variadic");
}
