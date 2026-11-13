{
  description = "ntcp: a standards-first, event-driven TCP stack in Rust";

  # The nixpkgs revision xylem pins, so both repositories build one identical DPDK.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/f9a75f41be3a74eab55d3a7679d34ad6cc0da977";

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};

      # nixpkgs' dpdk propagates rdma-core, so meson finds libibverbs and libmlx5 and builds
      # common/mlx5 and net/mlx5 next to net/ring; the dpdk-mlx5 check fails if that changes.
      # Both linkages are installed whatever default_library is: every library and PMD as .a
      # (whole-archived by ntcp-io-dpdk's static feature) and as .so, with the PMDs in the
      # plugin directory that a dynamically linked EAL loads at init. Static only links the
      # bundled tools such as dpdk-testpmd with every PMD. Nehalem (SSE4.2) runs on any
      # x86-64 host or VM CPU model in use, including the Cascade Lake VMs, whose exposed
      # CPU flags depend on the hypervisor; mlx5's x86 vector datapath is SSE code anyway.
      dpdk-mlx5 =
        (pkgs.dpdk.override {
          shared = false;
          machine = "nehalem";
        }).overrideAttrs
          (old: {
            # net/sfc needs libatomic for 128-bit atomics. GCC 16 links it implicitly, so
            # sfc's link check passed without it and libdpdk.pc never named it; rustc links
            # with -nodefaultlibs and then failed to link the static archives. Check without
            # the implicit library, and list libatomic in pkgconfig_extra_libs, as
            # drivers/meson.build requires for libraries found by find_library.
            postPatch = old.postPatch + ''
              substituteInPlace drivers/net/sfc/meson.build \
                --replace-fail \
                  "if not cc.links(atomic_check_code)" \
                  "if not cc.links(atomic_check_code, args: cc.get_supported_link_arguments('-fno-link-libatomic'))" \
                --replace-fail \
                  "    ext_deps += libatomic_dep" \
                  "    ext_deps += libatomic_dep
                    pkgconfig_extra_libs += '-latomic'"
            '';
          });

      # Libraries that libdpdk.pc names only for static linking (Requires.private and
      # Libs.private, with their own private requirements), so pkg-config --static resolves.
      dpdkStaticDeps = [
        pkgs.elfutils
        pkgs.intel-ipsec-mb
        pkgs.jansson
        pkgs.libnl # libpcap.pc
        pkgs.libpcap
        pkgs.numactl
        pkgs.openssl
        pkgs.zlib
        pkgs.zstd # libelf.pc
      ];
    in
    {
      packages.${system} = { inherit dpdk-mlx5; };

      # The PMDs exist in both linkages, and libdpdk.pc's static flags link every archive
      # without the C driver's implicit libatomic, as rustc's -nodefaultlibs links do.
      checks.${system}.dpdk-mlx5 =
        pkgs.runCommandCC "dpdk-mlx5-check"
          {
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ dpdk-mlx5 ] ++ dpdkStaticDeps;
          }
          ''
            for pmd in common_mlx5 net_mlx5 net_ring mempool_ring; do
              for lib in ${dpdk-mlx5}/lib/librte_$pmd.a ${dpdk-mlx5}/lib/dpdk/pmds-*/librte_$pmd.so; do
                [ -e "$lib" ] || { echo "missing $lib" >&2; exit 1; }
              done
            done
            echo 'int main(void) { return 0; }' > main.c
            cc main.c $(pkg-config --static --cflags --libs libdpdk) -fno-link-libatomic -o main
            touch $out
          '';

      # nixpkgs' C toolchain compiles the shim and links Rust binaries, so DPDK, rdma-core and
      # every binary built here share nix's glibc. ntcp-io-af-xdp's host feature compiles its
      # XDP program with clang-unwrapped: cc-wrapper's host-target flags do not apply to BPF;
      # tests/run-native.sh compiles its redirect program with the same compiler and flags.
      # stdenv already puts cc, ar, nm, make, patch, tar, sh and coreutils on PATH. Every
      # other tool a script or test runs comes from here, so `nix develop -i` works on a
      # machine with nothing but Nix; sudo, KVM, VFIO, hugepages and user namespaces stay
      # host features.
      devShells.${system}.default = pkgs.mkShell {
        NTCP_BPF_CLANG = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang";
        NTCP_BPF_CFLAGS = "-isystem ${pkgs.linuxHeaders}/include";
        packages = [
          pkgs.pkg-config
          pkgs.rustc
          pkgs.cargo
          pkgs.clippy
          pkgs.rustfmt
          # duvet/, integration/ and the crates' Python tests; tomllib needs Python 3.11.
          pkgs.python3
          # Source snapshots (rfc_host, check_mac_cost) and operator packetdrill checkouts.
          pkgs.git
          # integration/packetdrill/build_runner.py builds an operator checkout's runner.
          pkgs.bison
          pkgs.flex
          # Namespace tests: ip and tc (iproute2); unshare, nsenter, mount (util-linux);
          # offload control (ethtool); rfc_host's ICMP filters (nftables); the peer's
          # sysctls in linux_tun.py (procps); host_veth.py's ping (iputils).
          pkgs.iproute2
          pkgs.util-linux
          pkgs.ethtool
          pkgs.nftables
          pkgs.procps
          pkgs.iputils
          # ntcp-io-af-xdp/tests/run-native.sh pins and attaches its XDP program.
          pkgs.bpftools
          # ntcp-socket/tests/redis.py runs redis-server and redis-cli over the preload.
          pkgs.redis
        ];
        buildInputs = [
          dpdk-mlx5
          pkgs.rdma-core
          pkgs.libbpf
        ]
        ++ dpdkStaticDeps;
      };
    };
}
