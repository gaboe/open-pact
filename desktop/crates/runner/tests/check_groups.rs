//! The groups of the built-in checks. A group is display only: the manifest keeps
//! its own order.
use runner::manifest::{self, BUILTINS, Filter, Form, Group};

const MANIFEST: &str = include_str!("../../../tests/fixtures/manifest.toml");

fn group_of(id: &str) -> Group {
    manifest::builtin(id).unwrap().group
}

#[test]
fn every_built_in_check_has_a_group() {
    for known in &BUILTINS {
        assert_ne!(known.group, Group::Other, "{} is built in", known.id);
    }
}

#[test]
fn the_groups_hold_the_checks_the_task_names() {
    let expected = [
        (
            Group::DiskAndStartup,
            vec!["disk_encryption", "secure_boot", "preboot_auth"],
        ),
        (
            Group::SignIn,
            vec![
                "password_set",
                "password_min_length",
                "auto_login",
                "screen_lock",
            ],
        ),
        (
            Group::Updates,
            vec!["os_supported", "os_patch_age_days", "os_auto_updates"],
        ),
        (
            Group::MalwareAndNetwork,
            vec![
                "antimalware_active",
                "antimalware_realtime",
                "antimalware_signature_age_days",
                "antimalware_full_scan_age_days",
                "antimalware_active_threats",
                "web_protection",
                "firewall",
            ],
        ),
        (
            Group::LogsAndAudit,
            vec![
                "log_oldest_record_days",
                "log_cleared",
                "process_audit",
                "powershell_logging",
            ],
        ),
        (Group::LostDevice, vec!["remote_wipe"]),
        (Group::Account, vec!["work_account"]),
        (Group::Uptime, vec!["uptime_days"]),
        (
            Group::Repositories,
            vec!["managed_repos_outside", "managed_repos_total"],
        ),
    ];
    let mut named = 0;
    for (group, ids) in &expected {
        for id in ids {
            assert_eq!(group_of(id), *group, "{id}");
            named += 1;
        }
    }
    // Each ID is named once. An older version of a check shares its ID and its group.
    let newest = BUILTINS
        .iter()
        .filter(|known| manifest::builtin(known.id).is_some_and(|top| top.version == known.version))
        .count();
    assert_eq!(named, newest);
}

#[test]
fn the_headings_have_one_order_and_distinct_labels() {
    for (position, group) in Group::ALL.into_iter().enumerate() {
        assert_eq!(group as usize, position);
    }
    let labels: Vec<_> = Group::ALL.into_iter().map(Group::label).collect();
    assert_eq!(labels[0], "Disk and start-up");
    assert_eq!(labels[labels.len() - 1], "Other");
    let mut unique = labels.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), labels.len());
}

#[test]
fn grouping_the_table_keeps_the_manifest_order() {
    let form = Form::parse(MANIFEST).unwrap();
    let ids: Vec<_> = form.controls.iter().map(|c| c.id.clone()).collect();
    let sections = manifest::by_group(form.visible(Filter::All, ""), |index| {
        form.controls[*index].group()
    });
    let order: Vec<_> = sections.iter().map(|(group, _)| *group as usize).collect();
    assert!(order.windows(2).all(|pair| pair[0] < pair[1]), "{order:?}");
    for (group, indexes) in &sections {
        assert!(!indexes.is_empty());
        assert!(
            indexes.windows(2).all(|pair| pair[0] < pair[1]),
            "{group:?} is not in manifest order"
        );
        assert!(indexes.iter().all(|i| form.controls[*i].group() == *group));
    }
    let mut shown: Vec<_> = sections.into_iter().flat_map(|(_, i)| i).collect();
    shown.sort_unstable();
    assert_eq!(shown, (0..ids.len()).collect::<Vec<_>>());
    let again = Form::parse(MANIFEST).unwrap();
    let after: Vec<_> = again.controls.iter().map(|c| c.id.clone()).collect();
    assert_eq!(after, ids);
}

#[test]
fn a_check_that_is_not_built_in_goes_last_under_other() {
    let custom = MANIFEST.replace(
        "check = \"builtin:firewall@1\"",
        "check = \"custom:firewall\"",
    );
    let text = manifest::set_control_text(&custom, 1, "id", "firewall_custom").unwrap();
    let form = Form::parse(&text).unwrap();
    assert_eq!(form.controls[1].group(), Group::Other);
    let sections = manifest::by_group(form.visible(Filter::All, ""), |index| {
        form.controls[*index].group()
    });
    let (last, indexes) = sections.last().unwrap();
    assert_eq!(*last, Group::Other);
    assert_eq!(indexes, &[1]);
}

#[test]
fn the_add_check_list_shows_the_checks_under_the_same_headings() {
    let form = Form::parse(MANIFEST).unwrap();
    let sections = manifest::by_group(manifest::addable(&form), |known| known.group);
    let order: Vec<_> = sections.iter().map(|(group, _)| *group as usize).collect();
    assert!(order.windows(2).all(|pair| pair[0] < pair[1]), "{order:?}");
    assert!(
        sections
            .iter()
            .all(|(group, list)| list.iter().all(|known| known.group == *group))
    );
}
