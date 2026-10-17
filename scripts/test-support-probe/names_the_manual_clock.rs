//! Names the manual clock: compiles only with sealant-capture's `test-support`.

use sealant_capture::ManualClock;

fn main() {
    let manual = ManualClock::new();
    drop(manual.clock());
}
