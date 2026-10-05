//! [`restore_measure`]'s restore under an owner map (`RESTORE_MEASURE_OWNERS`, the JSON of
//! `SEALANT_CAPTURE_OWNER_MAP`), with the executor preparation boot makes for one timed with the
//! restore: the worktree root given to the change's owner and the group, and the group's default
//! ACL on it (`RESTORE_MEASURE_ACL=0` leaves the ACL out, to see what it costs). Root's work: run
//! it as root.
//!
//! ```text
//! RESTORE_MEASURE_OWNERS='{"gid":40000,"worktree":40012,"people":{"acct_a":40012}}' \
//! RESTORE_MEASURE_SOURCE=… RESTORE_MEASURE_STORE=… RESTORE_MEASURE_OUT=… \
//! cargo test -p sealant-capture --release --test restore_measure_owners -- --ignored --nocapture \
//!   restore_under_an_owner_map
//! ```

#[path = "restore_measure.rs"]
mod restore_measure;

use sealant_capture::owners::{OwnerMap, apply_default_acl};

#[test]
#[ignore = "a measurement over a real worktree, as root: set RESTORE_MEASURE_* and run with --ignored"]
fn restore_under_an_owner_map() {
    let json = std::env::var("RESTORE_MEASURE_OWNERS").expect("set RESTORE_MEASURE_OWNERS");
    let owners = OwnerMap::parse(&json).unwrap();
    let acl = std::env::var("RESTORE_MEASURE_ACL").as_deref() != Ok("0");
    restore_measure::measure(|root, targets| {
        owners.prepare_worktree_root(root).unwrap();
        if acl {
            apply_default_acl(&[root], owners.gid).unwrap();
        }
        targets.owners = Some(owners.clone());
    });
}
