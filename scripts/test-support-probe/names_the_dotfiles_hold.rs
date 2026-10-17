//! Names the dotfiles copy's hold seam: compiles only with sealantd's `test-support`.

use sealantd::test_support::DOTFILES_HOLD_ENV;

fn main() {
    println!("{DOTFILES_HOLD_ENV}");
}
