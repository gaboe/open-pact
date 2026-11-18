//! The admin app's control table and the core catalog list the same builtin checks, at the same versions.
use open_pact_core::{BUILTINS as CORE_BUILTINS, LATER_VERSIONS};
use runner::manifest::BUILTINS;
use std::collections::BTreeSet;

#[test]
fn the_app_table_lists_the_core_builtins() {
    let core: BTreeSet<(&str, u32)> = CORE_BUILTINS
        .iter()
        .chain(LATER_VERSIONS.iter())
        .map(|(id, version)| (*id, *version))
        .collect();
    let app: BTreeSet<(&str, u32)> = BUILTINS
        .iter()
        .map(|known| (known.id, u32::from(known.version)))
        .collect();
    assert_eq!(
        BUILTINS.len(),
        core.len(),
        "the app table has a duplicate or a gap"
    );
    assert_eq!(app, core);
}
