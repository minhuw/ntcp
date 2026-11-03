//! ntcp-pathctl: owner-authorized administration of an ntcp Host's routes
//! and paths through its local control socket. See `ntcp_path_control::cli`.

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::ExitCode::from(ntcp_path_control::cli::main(&args))
}
