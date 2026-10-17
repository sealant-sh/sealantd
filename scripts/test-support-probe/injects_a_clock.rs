//! Puts a clock in a `CaptureConfig`: compiles only with sealant-capture's `test-support`.

fn main() {
    let mut config = sealant_capture::CaptureConfig::new("probe", 1, std::path::Path::new("/"));
    config.clock = sealant_capture::Clock::real();
    drop(config);
}
