# Userland tools: bedrock-cli and bedrock-determinism
{ pkgs }:

let
  src = pkgs.lib.cleanSourceWith {
    src = ./..;
    filter = path: type:
      let baseName = builtins.baseNameOf path; in
      # Exclude kernel module build artifacts and non-cargo dirs
      !(baseName == "target" ||
        baseName == ".git" ||
        baseName == ".claude" ||
        baseName == "nix" ||
        # Exclude the kernel module crate (no Cargo.toml, breaks workspace)
        (type == "directory" && baseName == "bedrock" &&
         builtins.match ".*/crates/bedrock$" path != null));
  };
in
{
  bedrock-cli = pkgs.rustPlatform.buildRustPackage {
    pname = "bedrock-cli";
    version = "0.1.0";
    inherit src;
    cargoLock.lockFile = ../Cargo.lock;
    cargoBuildFlags = [ "-p" "bedrock-cli" ];
    # Build the binary only — don't run the (unscoped) workspace test suite,
    # which gates the build on unrelated crates' tests (e.g. bedrock-vmx's
    # flaky global-VPID-allocator test). Tests run via `just test`.
    doCheck = false;
    meta.mainProgram = "bedrock-cli";
  };

  bedrock-determinism = pkgs.rustPlatform.buildRustPackage {
    pname = "bedrock-determinism";
    version = "0.1.0";
    inherit src;
    cargoLock.lockFile = ../Cargo.lock;
    cargoBuildFlags = [ "-p" "bedrock-determinism-tests" ];
    doCheck = false;
    meta.mainProgram = "bedrock-determinism";
  };

  lonepine = pkgs.rustPlatform.buildRustPackage {
    pname = "lonepine";
    version = "0.1.0";
    inherit src;
    cargoLock.lockFile = ../Cargo.lock;
    cargoBuildFlags = [ "-p" "lonepine" ];
    # Don't run the workspace test suite as part of building the binary: the
    # check phase would `cargo test` the whole workspace (unscoped by the build
    # flags), which both wastes time and gates the binary on unrelated crates'
    # tests (e.g. bedrock-vmx's global-VPID-allocator test, which is flaky under
    # parallel `cargo test`). Tests are run via `just test`. Mirrors the
    # workload-monitor package in nix/podman-initrd.nix.
    doCheck = false;
    meta.mainProgram = "lonepine";
  };
}
