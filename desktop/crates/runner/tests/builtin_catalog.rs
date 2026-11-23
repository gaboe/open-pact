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

fn entry(check: &str) -> &'static runner::manifest::Builtin {
    runner::manifest::builtin_of_check(check).unwrap()
}

#[test]
fn both_scan_age_versions_share_one_title_and_name_their_sources() {
    let first = entry("builtin:antimalware_full_scan_age_days@1");
    let later = entry("builtin:antimalware_full_scan_age_days@2");
    assert_eq!(first.name, "Malware scan age");
    assert_eq!(later.name, "Malware scan age");
    // Version 1 is the Windows Defender full scan and nothing else.
    assert!(
        first.line.contains("Windows Defender full scan"),
        "{}",
        first.line
    );
    assert!(!first.line.contains("Remediator"), "{}", first.line);
    assert!(!first.noun.contains("Remediator"), "{}", first.noun);
    // Version 2 names both sources and says that canceled runs do not count.
    for text in [later.line, later.noun] {
        assert!(text.contains("Windows Defender full scan"), "{text}");
        assert!(text.contains("macOS XProtect Remediator scan"), "{text}");
        assert!(text.contains("canceled runs do not count"), "{text}");
    }
}

#[test]
fn active_threats_version_two_says_what_macos_reports() {
    let later = entry("builtin:antimalware_active_threats@2");
    assert!(later.line.contains("Windows count"), "{}", later.line);
    assert!(
        later
            .line
            .contains("macOS 0 or unknown from XProtect Remediator"),
        "{}",
        later.line
    );
}
