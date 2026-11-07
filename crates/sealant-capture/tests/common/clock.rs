//! Run synchronous capture operations while advancing their injected clock.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use sealant_capture::clock::ManualClock;

/// Register the caller before advancing, then stop as soon as it leaves the clock. Work and
/// thread scheduling take no virtual time; every sleep still runs for its full duration.
pub(crate) fn on_clock<T: Send>(
    manual: &ManualClock,
    run: impl FnOnce() -> T + Send,
) -> (T, Duration) {
    let start = manual.now();
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let (ready, started) = mpsc::sync_channel(0);
        let finished = &done;
        let clock = manual.clock();
        let task = scope.spawn(move || {
            let entered = clock.enter();
            ready.send(()).unwrap();
            let result = run();
            let took = clock.now() - start;
            finished.store(true, Ordering::SeqCst);
            drop(entered);
            (result, took)
        });
        started.recv().unwrap();
        loop {
            manual.settle();
            if done.load(Ordering::SeqCst) || task.is_finished() {
                break;
            }
            manual.advance_next(manual.now() + Duration::from_secs(1));
        }
        task.join().unwrap()
    })
}
