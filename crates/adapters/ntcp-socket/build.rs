fn main() {
    println!("cargo:rerun-if-changed=src/variadic.c");
    cc::Build::new()
        .file("src/variadic.c")
        .compile("ntcp_variadic");
}
