//! The sending section: each part on or off, the values a part keeps while it is off, the older
//! flat [schedule] it converts, and the forgetting of kept values when the draft is replaced.
use runner::manifest::{self, Form, KeptSends, SendPart};

const FLAT_VPN: &str = "manifest_version = 1

[schedule]
mode = \"vpn\"
vpn_probe = \"10.0.0.2:443\"
vpn_probe_name = \"Office VPN\"
interval = \"1h\"
";

const FLAT_ALWAYS: &str = "manifest_version = 1

[schedule]
mode = \"always\"
interval = \"6h\"
";

const NONE: &str = "manifest_version = 1\n";

fn form(text: &str) -> Form {
    Form::parse(text).unwrap()
}

#[test]
fn an_older_vpn_schedule_converts_when_its_section_is_edited() {
    assert_eq!(form(FLAT_VPN).schedule.unwrap().vpn.unwrap().interval, "1h");
    let text = manifest::set_send_text(FLAT_VPN, SendPart::Vpn, "interval", "2h").unwrap();
    assert!(!text.contains("mode ="), "{text}");
    assert!(!text.contains("vpn_probe"), "{text}");
    assert!(text.contains("[schedule.vpn]"), "{text}");
    let schedule = form(&text).schedule.unwrap();
    let vpn = schedule.vpn.unwrap();
    assert_eq!(vpn.probe, "10.0.0.2:443");
    assert_eq!(vpn.name, "Office VPN");
    assert_eq!(vpn.interval, "2h");
    assert!(schedule.always.is_none());
}

#[test]
fn an_older_always_schedule_becomes_the_any_network_part() {
    let mut kept = KeptSends::default();
    let text = manifest::switch_send(FLAT_ALWAYS, SendPart::Vpn, true, &mut kept).unwrap();
    let schedule = form(&text).schedule.unwrap();
    assert_eq!(schedule.always.unwrap().interval, "6h");
    assert_eq!(schedule.vpn.unwrap().probe, "");
    assert!(text.contains("[schedule.always]"), "{text}");
}

#[test]
fn a_part_keeps_its_values_while_it_is_off_and_restores_them() {
    let mut kept = KeptSends::default();
    let off = manifest::switch_send(FLAT_VPN, SendPart::Vpn, false, &mut kept).unwrap();
    assert!(form(&off).schedule.is_none());
    assert_eq!(kept.vpn.as_ref().unwrap().probe, "10.0.0.2:443");
    let on = manifest::switch_send(&off, SendPart::Vpn, true, &mut kept).unwrap();
    let vpn = form(&on).schedule.unwrap().vpn.unwrap();
    assert_eq!(vpn.probe, "10.0.0.2:443");
    assert_eq!(vpn.name, "Office VPN");
    assert_eq!(vpn.interval, "1h");
    assert_eq!(vpn.check, "5m");
}

#[test]
fn both_parts_off_leave_no_schedule_and_both_on_write_two_tables() {
    let mut kept = KeptSends::default();
    let both = manifest::switch_send(NONE, SendPart::Always, true, &mut kept).unwrap();
    let both = manifest::switch_send(&both, SendPart::Vpn, true, &mut kept).unwrap();
    let schedule = form(&both).schedule.unwrap();
    assert_eq!(schedule.always.unwrap().interval, "24h");
    assert_eq!(schedule.vpn.unwrap().interval, "1h");
    let none = manifest::switch_send(&both, SendPart::Always, false, &mut kept).unwrap();
    let none = manifest::switch_send(&none, SendPart::Vpn, false, &mut kept).unwrap();
    assert!(form(&none).schedule.is_none());
    assert!(!none.contains("[schedule"), "{none}");
    assert_eq!(kept.always.unwrap().interval, "24h");
}

#[test]
fn a_part_switched_on_from_nothing_gets_its_defaults() {
    let mut kept = KeptSends::default();
    let text = manifest::switch_send(NONE, SendPart::Vpn, true, &mut kept).unwrap();
    let vpn = form(&text).schedule.unwrap().vpn.unwrap();
    assert_eq!(
        (
            vpn.probe.as_str(),
            vpn.check.as_str(),
            vpn.interval.as_str()
        ),
        ("", "5m", "1h")
    );
    assert!(
        !text.contains("check"),
        "the default check is not written: {text}"
    );
}

#[test]
fn a_section_value_edit_keeps_the_other_part() {
    let mut kept = KeptSends::default();
    let both = manifest::switch_send(FLAT_ALWAYS, SendPart::Vpn, true, &mut kept).unwrap();
    let edited = manifest::set_send_text(&both, SendPart::Vpn, "probe", "10.0.0.9:443").unwrap();
    let schedule = form(&edited).schedule.unwrap();
    assert_eq!(schedule.vpn.unwrap().probe, "10.0.0.9:443");
    assert_eq!(schedule.always.unwrap().interval, "6h");
    assert!(manifest::set_send_text(NONE, SendPart::Vpn, "interval", "1h").is_err());
}

#[test]
fn a_remembered_pair_is_gone_after_the_draft_is_replaced_as_a_whole() {
    // Discard, Refresh, Setup and Apply or Restore each replace the draft with another text and
    // forget the remembered values. A turned-on part then starts from its defaults.
    let replacements = [
        ("discard", FLAT_ALWAYS),
        ("refresh", FLAT_ALWAYS),
        ("setup for another gateway", NONE),
        ("restore", FLAT_ALWAYS),
    ];
    for (case, replacement) in replacements {
        let mut kept = KeptSends::default();
        manifest::switch_send(FLAT_VPN, SendPart::Vpn, false, &mut kept).unwrap();
        assert!(kept.vpn.is_some(), "{case}: the pair is remembered first");
        kept.forget();
        let text = manifest::switch_send(replacement, SendPart::Vpn, true, &mut kept).unwrap();
        let vpn = form(&text).schedule.and_then(|s| s.vpn);
        assert_eq!(vpn.map(|v| v.probe), Some(String::new()), "{case}");
    }
}

#[test]
fn a_toml_edit_that_changes_the_schedule_forgets_the_pair() {
    let mut kept = KeptSends::default();
    manifest::switch_send(FLAT_VPN, SendPart::Vpn, false, &mut kept).unwrap();
    let edited = FLAT_VPN.replace("10.0.0.2:443", "10.0.0.7:443");
    manifest::sends_after_edit(FLAT_VPN, &edited, &mut kept);
    assert_eq!(kept, KeptSends::default());
}

#[test]
fn a_toml_edit_that_keeps_the_schedule_keeps_the_pair() {
    let mut kept = KeptSends::default();
    manifest::switch_send(FLAT_VPN, SendPart::Vpn, false, &mut kept).unwrap();
    let before = kept.clone();
    let edited = format!("{FLAT_VPN}# a comment\n").replace("issuer", "issuer");
    manifest::sends_after_edit(FLAT_VPN, &edited, &mut kept);
    assert_eq!(kept, before);
}

/// The text of one [[control]] table, counted from zero.
fn control_block(text: &str, index: usize) -> &str {
    text.split("[[control]]").nth(index + 1).unwrap()
}

#[test]
fn a_written_control_takes_the_current_names_and_drops_source() {
    let before = manifest::set_control_text(
        include_str!("../../../tests/fixtures/manifest.toml"),
        1,
        "description",
        "Keep it on.",
    )
    .unwrap();
    assert_eq!(form(&before).controls[1].description, "Keep it on.");
    assert!(control_block(&before, 1).contains("description = \"Keep it on.\""));
    assert!(!control_block(&before, 1).contains("source ="), "{before}");
    let text = manifest::set_control_text(&before, 0, "reference", "Annex 4.2").unwrap();
    let disk = control_block(&text, 0);
    assert!(disk.contains("reference = \"Annex 4.2\""), "{disk}");
    assert!(
        disk.contains("description = \"A lost laptop must not expose client data.\""),
        "{disk}"
    );
    assert!(!disk.contains("source"), "{disk}");
    assert!(!disk.contains("rationale"), "{disk}");
    let read = &form(&text).controls[0];
    assert_eq!(
        (read.reference.as_str(), read.description.as_str()),
        ("Annex 4.2", "A lost laptop must not expose client data.")
    );
}

#[test]
fn a_screen_lock_check_offers_minutes_as_its_newest_version() {
    let offered = manifest::addable(&form(NONE));
    let lock = offered
        .iter()
        .find(|known| known.id == "screen_lock")
        .unwrap();
    assert_eq!(lock.version, 2);
    let (text, index) = manifest::add_control(NONE, "screen_lock").unwrap();
    let added = &form(&text).controls[index];
    assert_eq!(added.check, "builtin:screen_lock@2");
    assert_eq!(added.limit_unit(), "minutes");
    assert!(added.limit_is_max());
    let old = form(include_str!("../../../tests/fixtures/manifest.toml"));
    let screen = old.control("screen_lock").unwrap();
    assert_eq!(screen.check, "builtin:screen_lock@1");
    assert_eq!(screen.name(), "Screen lock");
    assert!(
        !manifest::addable(&old)
            .iter()
            .any(|known| known.id == "screen_lock")
    );
}
