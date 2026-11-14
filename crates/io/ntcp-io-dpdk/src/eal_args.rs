// The device contract `Eal::init` checks before EAL sees its arguments.
// Without an allow-list DPDK probes every supported PCI device it finds; on
// bifurcated mlx5 in non-isolated mode that takes all traffic of every
// ConnectX port from the kernel, the management (SSH) port included, which
// cuts a remote host off. So the arguments must name the devices (`-a`) or
// exclude PCI (`--no-pci`).
//
// Arguments are split as DPDK 26.03's EAL parser (lib/argparse, options in
// lib/eal/common/eal_option_list.h) splits them, so the guard sees what EAL
// sees: option names match exactly; `--` ends EAL's arguments; arguments not
// starting with `-` are skipped; a value is attached after the first `=`
// (`--allow=X`, `-a=X`), or after a short option's two characters (`-aX`), or
// else, for an option that requires one, is the next argument whatever it
// looks like.

use std::io;

// Options that require a value (LIST_ARG, STR_ARG, STR_ALIAS in DPDK 26.03),
// plus the removed `-w`/`--pci-whitelist`, which took one.
const VALUE_OPTIONS: &[&str] = &[
    "-a",
    "--allow",
    "-b",
    "--block",
    "-c",
    "--coremask",
    "-d",
    "--driver-path",
    "-l",
    "--lcores",
    "-m",
    "--memory-size",
    "-n",
    "--memory-channels",
    "-r",
    "--memory-ranks",
    "-S",
    "--service-corelist",
    "-s",
    "--service-coremask",
    "--base-virtaddr",
    "--file-prefix",
    "--force-max-simd-bitwidth",
    "--huge-dir",
    "--iova-mode",
    "--log-level",
    "--main-lcore",
    "--mbuf-pool-ops-name",
    "--numa-limit",
    "--numa-mem",
    "--proc-type",
    "--socket-limit",
    "--socket-mem",
    "--trace",
    "--trace-bufsz",
    "--trace-dir",
    "--trace-mode",
    "--vdev",
    "--vfio-intr",
    "--vfio-vf-token",
    "-w",
    "--pci-whitelist",
];

const DEFAULT_PROBE: &str = "without an allow-list DPDK probes every supported PCI \
device, and on bifurcated mlx5 that takes all traffic of every ConnectX port from the \
kernel, the management (SSH) port included";

fn refuse(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Refuses EAL arguments (without a program name) that contain a NUL or would
/// let EAL probe PCI devices implicitly. Accepted: one or more allow-list
/// entries (`-a X`, `-aX`, `-a=X`, `--allow X`, `--allow=X`) naming a device,
/// or `--no-pci`. Refused: neither (also with only `--vdev`, which does not
/// stop the PCI probe); a block-list without an allow-list; both lists (EAL
/// refuses them too); an allow entry with no device before its first `,`;
/// `--no-pci` with an allow-list; the removed `-w`/`--pci-whitelist`.
pub(crate) fn check(args: &[String]) -> io::Result<()> {
    if args.iter().any(|arg| arg.contains('\0')) {
        return Err(refuse("EAL argument contains NUL".into()));
    }
    let (mut allow, mut block, mut no_pci, mut vdev) = (false, false, false, false);
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg == "--" {
            break;
        }
        if !arg.starts_with('-') {
            continue;
        }
        let (name, attached) = match arg.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None if !arg.starts_with("--") && arg.len() > 2 => match arg.split_at_checked(2) {
                Some((name, value)) => (name, Some(value)),
                None => (arg.as_str(), None),
            },
            None => (arg.as_str(), None),
        };
        let value = match attached {
            None if VALUE_OPTIONS.contains(&name) => rest.next().map(String::as_str),
            value => value,
        };
        match name {
            "-a" | "--allow" => {
                let value = value.unwrap_or("");
                if value.split(',').next().unwrap_or("").trim().is_empty() {
                    return Err(refuse(format!(
                        "EAL argument `{name}` with value {value:?} names no device (a \
                         missing PCI address?): `{name}` takes `<pci>[,key=value]...`; \
                         {DEFAULT_PROBE}"
                    )));
                }
                allow = true;
            }
            "-b" | "--block" => block = true,
            "--no-pci" if attached.is_none() => no_pci = true,
            "--vdev" => vdev = true,
            "-w" | "--pci-whitelist" => {
                return Err(refuse(format!(
                    "EAL argument `{name}` is not an option of DPDK 26.03 (replaced by \
                     `-a`/`--allow` in DPDK 20.11): use `-a <pci>`"
                )));
            }
            _ if name.starts_with("-a") && !name.starts_with("--") => {
                return Err(refuse(format!(
                    "EAL argument `{arg}`: EAL splits an option at its first `=` and reads \
                     `{name}`, not `-a`: write `-a <pci>,key=value` or `--allow=<pci>,key=value`"
                )));
            }
            _ => {}
        }
    }
    match (allow, block, no_pci) {
        (true, _, true) => Err(refuse(
            "EAL arguments have both `--no-pci` and an allow-list (`-a`): `--no-pci` keeps \
             the allowed PCI devices from being probed; pass `-a <pci>` or `--no-pci`, not both"
                .into(),
        )),
        (true, true, false) => Err(refuse(
            "EAL arguments have both an allow-list (`-a`) and a block-list (`-b`/`--block`), \
             which EAL refuses: pass only `-a <pci>`"
                .into(),
        )),
        (true, false, false) | (false, _, true) => Ok(()),
        (false, true, false) => Err(refuse(format!(
            "EAL arguments have a block-list (`-b`/`--block`) but no allow-list: EAL still \
             probes every device not blocked; pass `-a <pci>` for each device instead; \
             {DEFAULT_PROBE}"
        ))),
        (false, false, false) if vdev => Err(refuse(format!(
            "EAL arguments have `--vdev` but neither `-a <pci>` nor `--no-pci`: `--vdev` does \
             not stop the PCI probe; add `--no-pci` for virtual devices only; {DEFAULT_PROBE}"
        ))),
        (false, false, false) => Err(refuse(format!(
            "EAL arguments have no device allow-list: pass `-a <pci>` (`--allow`) for each \
             device to probe, or `--no-pci` for virtual devices only; {DEFAULT_PROBE}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_args(args: &[&str]) -> io::Result<()> {
        check(&args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>())
    }

    // The refusal, which must name `flag`.
    fn refused(args: &[&str], flag: &str) -> String {
        let error = check_args(args).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let message = error.to_string();
        assert!(message.contains(flag), "{message:?} does not name {flag}");
        message
    }

    #[test]
    fn accepts_an_allow_entry_with_its_value_next() {
        check_args(&["-l", "0", "-a", "0000:3b:00.0"]).unwrap();
        check_args(&["--allow", "0000:3b:00.0,dv_flow_en=1", "--in-memory"]).unwrap();
    }

    #[test]
    fn accepts_an_attached_allow_entry() {
        check_args(&["-a0000:3b:00.0"]).unwrap();
        check_args(&["-a=0000:3b:00.0,dv_flow_en=1"]).unwrap();
        check_args(&["--allow=0000:3b:00.0,dv_flow_en=1"]).unwrap();
    }

    #[test]
    fn accepts_several_allow_entries() {
        check_args(&[
            "-a",
            "0000:3b:00.0",
            "--allow=0000:3b:00.1",
            "-a0000:5e:00.0",
        ])
        .unwrap();
    }

    #[test]
    fn accepts_no_pci_alone_or_with_virtual_devices() {
        check_args(&["--no-pci", "--no-huge"]).unwrap();
        check_args(&["--vdev", "net_ring0", "--no-pci"]).unwrap();
        check_args(&["--vdev=net_tap0,iface=x", "--no-pci"]).unwrap();
        // Blocking under --no-pci probes nothing either.
        check_args(&["--no-pci", "-b", "0000:3b:00.0"]).unwrap();
    }

    #[test]
    fn refuses_no_allow_list() {
        let message = refused(&["-l", "0", "--in-memory"], "-a <pci>");
        assert!(message.contains("--no-pci"));
        assert!(message.contains("management (SSH) port"));
        refused(&[], "-a <pci>");
    }

    #[test]
    fn refuses_virtual_devices_without_no_pci() {
        let message = refused(&["--vdev", "net_ring0"], "--no-pci");
        assert!(message.contains("--vdev"));
    }

    #[test]
    fn refuses_a_block_list_without_an_allow_list() {
        let message = refused(&["-b", "0000:3b:00.0"], "-b");
        assert!(message.contains("-a <pci>"));
        refused(&["--block=0000:3b:00.0"], "--block");
    }

    #[test]
    fn refuses_allow_and_block_lists_together() {
        refused(&["-a", "0000:3b:00.0", "-b", "0000:3b:00.1"], "-b");
    }

    #[test]
    fn refuses_an_allow_entry_without_a_device() {
        refused(&["-a", ",dv_flow_en=1"], "`-a`");
        refused(&["-a", ""], "`-a`");
        refused(&["--allow="], "`--allow`");
        refused(&["-a=,dv_flow_en=1"], "`-a`");
        // The value is missing altogether.
        refused(&["--in-memory", "-a"], "`-a`");
    }

    #[test]
    fn refuses_no_pci_with_an_allow_list() {
        let message = refused(&["--no-pci", "-a", "0000:3b:00.0"], "--no-pci");
        assert!(message.contains("-a"));
    }

    #[test]
    fn refuses_the_removed_whitelist_options() {
        let message = refused(&["-w", "0000:3b:00.0"], "`-w`");
        assert!(message.contains("-a <pci>"));
        refused(&["-w0000:3b:00.0"], "`-w`");
        refused(&["--pci-whitelist=0000:3b:00.0"], "`--pci-whitelist`");
    }

    #[test]
    fn refuses_an_attached_allow_entry_with_pmd_arguments() {
        // EAL reads option `-a0000:3b:00.0,dv_flow_en`, which it does not know.
        refused(&["-a0000:3b:00.0,dv_flow_en=1"], "`-a <pci>,key=value`");
    }

    #[test]
    fn ignores_flags_eal_does_not_read_as_options() {
        // Values of other options, and everything after `--`.
        refused(&["--file-prefix", "-a", "0000:3b:00.0"], "-a <pci>");
        refused(&["--log-level", "--no-pci"], "-a <pci>");
        refused(&["--", "-a", "0000:3b:00.0"], "-a <pci>");
        refused(&["--lcores", "--no-pci"], "-a <pci>");
        // An attached value consumes nothing.
        check_args(&["--file-prefix=x", "-a", "0000:3b:00.0"]).unwrap();
        check_args(&["-l0", "--no-pci"]).unwrap();
    }

    #[test]
    fn refuses_nul() {
        refused(&["--no-pci", "-a\0"], "NUL");
    }
}
