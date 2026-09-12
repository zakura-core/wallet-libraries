//! Generates the gRPC client from the checked-in protocol definitions.
//!
//! The generated code is written into `OUT_DIR` rather than the source tree, so
//! the definitions here are the only copy to keep in step with the server.
//! `protoc` is required to build this crate; it is the one crate in the wallet
//! core with a build-time tool dependency, which is part of why the transport
//! is a crate of its own.

use std::{env, io, path::PathBuf};

fn main() -> io::Result<()> {
    if env::var_os("PROTOC")
        .map(PathBuf::from)
        .or_else(|| which::which("protoc").ok())
        .is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "protoc is required to build zakura-wallet-lwd; install it, or set PROTOC",
        ));
    }

    println!("cargo:rerun-if-changed=proto/compact_formats.proto");
    println!("cargo:rerun-if-changed=proto/service.proto");

    // The server side is generated only for the fixture light server, which
    // tests and rehearsals run against; the wallet itself is a client.
    let server = env::var_os("CARGO_FEATURE_FIXTURE_SERVER").is_some();
    tonic_prost_build::configure()
        .build_server(server)
        .compile_protos(
            &["proto/service.proto", "proto/compact_formats.proto"],
            &["proto"],
        )
}
