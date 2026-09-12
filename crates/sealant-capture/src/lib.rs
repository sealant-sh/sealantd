//! Session capture store engine (ADR-0015): the executor-side half of the capture store.
//!
//! A workspace is captured as two classes of content-addressed objects in a bucket-shaped
//! [`sink::BlobSink`]: git objects as self-contained git packs ([`gitpack`]), everything else as
//! content-defined chunks in CDC packs ([`chunk`], [`pack`]) described by dir objects ([`tree`]).
//! A [`manifest::Manifest`] ties one capture together; [`ship`] stages and uploads it and
//! registers it through a [`registrar::Registrar`]; [`materialize`] rebuilds a workspace from a
//! manifest. [`CaptureEngine`] is the front door.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod chunk;
pub mod engine;
pub mod gitpack;
pub mod index;
pub mod keys;
pub mod manifest;
pub mod materialize;
pub mod pack;
pub mod registrar;
pub mod ship;
pub mod sink;
pub mod tree;

pub use engine::{
    Cadence, CaptureConfig, CaptureEngine, Class, EngineError, SnapRequest, SnapStats,
    StagedCapture,
};
pub use manifest::{CaptureKind, EncodedManifest, FsckStatus, Manifest};
pub use materialize::{MaterializeClass, MaterializeReport, MaterializeTargets, Materializer};
pub use registrar::{HttpRegistrar, InMemoryRegistrar, Registrar, RegistrarError};
pub use ship::{ShipSnapshot, ShipWorker, Shipper, Staging};
pub use sink::{BlobSink, LocalDir, PresignedHttp, UrlMinter};
