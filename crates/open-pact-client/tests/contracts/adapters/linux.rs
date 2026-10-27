use super::*;
use crate::checks::contracts::Case;
use open_pact_core::ControlValue;

pub(crate) fn run(id: &str, case: &Case) -> ControlValue {
    let text = case.text(0);
    match id {
        "disk_encryption" => parse_lsblk_inverse(text).into(),
        "firewall" => merge_firewall(
            parse_firewall_cmd(text),
            ufw_enabled(
                case.optional(1),
                case.optional(2).and_then(parse_systemctl_unit),
            ),
        )
        .into(),
        "screen_lock" => if case.input.len() == 1 {
            parse_kscreenlocker(text)
        } else {
            parse_gnome_lock(text, case.text(1), case.text(2))
        }
        .into(),
        "os_supported" => parse_os_supported(text, case.now().date_naive()).into(),
        "auto_login" => {
            aggregate_autologin(&case.input.iter().flatten().cloned().collect::<Vec<_>>()).into()
        }
        "secure_boot" => parse_mokutil(text).into(),
        "antimalware_active" => parse_antimalware_units(text).into(),
        "os_patch_age_days" => patch_age(&Fixture(case), case.now()),
        _ => panic!("unsupported Linux contract {id}"),
    }
}

struct Fixture<'a>(&'a Case);
impl PackageHost for Fixture<'_> {
    fn read(&self, _: &str) -> Option<String> {
        None
    }
    fn run(&self, program: &str, args: &[&str]) -> Option<Ran> {
        assert_eq!(program, "dnf");
        let index = if args == ["history", "list"] {
            0
        } else {
            assert_eq!(args, ["-C", "-q", "updateinfo", "list", "--security"]);
            1
        };
        self.0.optional(index).map(|text| Ran {
            success: self.0.code == Some(0),
            text: text.into(),
        })
    }
    fn list(&self, _: &str) -> Option<Vec<String>> {
        None
    }
    fn digest(&self, _: &str, _: bool, _: Hash) -> Option<IndexDigest> {
        None
    }
    fn stamp(&self, _: &str) -> Option<String> {
        None
    }
}
