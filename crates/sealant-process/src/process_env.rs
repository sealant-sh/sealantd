//! Setting the daemon's own environment, once, before any thread exists: what a microVM's PID 1
//! (`sealantd --vm`) does with the image's `PATH` and a few daemon settings, which the kernel
//! never gave it. In edition 2024 `std::env::set_var` is `unsafe` because another thread may be
//! reading the environment; this checks that no other thread exists, and refuses otherwise.
#![allow(unsafe_code)]

/// How many threads this process has (`/proc/self/status`), when it can be read.
#[must_use]
pub fn thread_count() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .and_then(|count| count.trim().parse().ok())
}

/// Set each `(key, value)` in this process's environment.
///
/// # Errors
/// The process has more than one thread (or the count cannot be read), so setting the
/// environment could race a reader: nothing is set. A key that is empty or holds `=` or NUL,
/// or a value holding NUL, is refused before anything is set.
pub fn set_while_single_threaded(pairs: &[(String, String)]) -> Result<(), String> {
    for (key, value) in pairs {
        if key.is_empty() || key.contains(['=', '\0']) || value.contains('\0') {
            return Err(format!("{key:?} is not a settable environment entry"));
        }
    }
    match thread_count() {
        Some(1) => {}
        Some(n) => {
            return Err(format!(
                "{n} threads are running; the environment is left alone"
            ));
        }
        None => {
            return Err("the thread count cannot be read; the environment is left alone".into());
        }
    }
    for (key, value) in pairs {
        // SAFETY: this process has exactly one thread (checked just above, and this function
        // starts none), so nothing can read the environment while it is written.
        unsafe { std::env::set_var(key, value) };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_process_with_other_threads_is_left_alone() {
        // The test harness runs each test on a thread of its own: more than one thread.
        assert!(thread_count().is_some_and(|n| n > 1));
        let key = "SEALANT_PROCESS_ENV_TEST_NEVER_SET".to_owned();
        assert!(set_while_single_threaded(&[(key.clone(), "x".to_owned())]).is_err());
        assert!(std::env::var(&key).is_err());
    }

    #[test]
    fn a_malformed_entry_is_refused_before_anything_is_set() {
        for (key, value) in [("", "v"), ("A=B", "v"), ("A", "v\0")] {
            assert!(
                set_while_single_threaded(&[(key.to_owned(), value.to_owned())])
                    .unwrap_err()
                    .contains("not a settable")
            );
        }
    }
}
