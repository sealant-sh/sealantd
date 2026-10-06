fn main() {
    // Use a vendored protoc so the build needs no system protobuf-compiler on any platform (ADR-0012).
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc binary");
    // SAFETY: build scripts run single-threaded here; this only points prost-build at our protoc.
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }
    prost_build::Config::new()
        // The status report is the largest result by far; boxed, it does not size every other.
        .boxed(".sealant.v1.CommandResult.result.capture_status")
        .boxed(".sealant.v1.CommandResult.result.capabilities")
        // A dotfiles repository carries several strings: boxed, it does not size every command.
        .boxed(".sealant.v1.Command.command.dotfiles_apply")
        .compile_protos(&["proto/sealant.proto"], &["proto"])
        .expect("compile sealant.proto");
    println!("cargo:rerun-if-changed=proto/sealant.proto");
}
