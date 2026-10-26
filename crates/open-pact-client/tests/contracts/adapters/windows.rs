use super::*;
use crate::checks::contracts::{Case, load};
use std::cell::RefCell;

thread_local! {
    static CURRENT: RefCell<Option<(String, String)>> = const { RefCell::new(None) };
}
static FIXTURES: OnceLock<BTreeMap<(String, String), Batch>> = OnceLock::new();

fn fixture(id: &str, case: &Case) -> Batch {
    let key = match id {
        "disk_encryption" => "bitlocker",
        "os_supported" => "os",
        "os_patch_age_days" => "patch_date",
        "auto_login" => "autologin",
        "antimalware_active" => "antimalware",
        "preboot_auth" => "preboot",
        "antimalware_signature_age_days" => "signature_days",
        "antimalware_full_scan_age_days" => "full_scan_days",
        "log_oldest_record_days" => "log_retention",
        "screen_lock" => "lock_policy",
        "web_protection" => "smartscreen",
        other => other,
    };
    let text = match id {
        "screen_lock" if case.input.len() == 1 => {
            format!("lock_policy\t0\nscreen_savers\t{}\n", case.text(0))
        }
        "screen_lock" => format!(
            "lock_policy\t{}\nscreen_savers\t{}\n",
            case.text(0),
            case.text(1)
        ),
        "web_protection" => format!(
            "smartscreen\t{}\nbrowsers\t{}\n",
            case.text(0),
            case.text(1)
        ),
        _ if case.optional(0).is_none() => String::new(),
        _ => format!("{key}\t{}\n", case.text(0)),
    };
    Batch {
        values: parse_values(&text),
        diagnostics: "fictional contract batch".into(),
        completed: case.code == Some(0),
    }
}

pub(super) fn batch() -> Option<&'static Batch> {
    let key = CURRENT.with(|current| current.borrow().clone())?;
    FIXTURES
        .get_or_init(|| {
            load()
                .into_iter()
                .flat_map(|contract| {
                    contract
                        .cases
                        .into_iter()
                        .filter(|case| case.seam == "windows" && case.known_diff.is_none())
                        .map(move |case| {
                            let batch = fixture(&contract.id, &case);
                            ((contract.id.clone(), case.name), batch)
                        })
                })
                .collect()
        })
        .get(&key)
}

pub(crate) fn run(id: &str, case: &Case) -> ControlValue {
    CURRENT.with(|current| *current.borrow_mut() = Some((id.into(), case.name.clone())));
    let check = crate::checks::WINDOWS
        .iter()
        .find(|(name, _)| *name == id)
        .unwrap()
        .1;
    let result = check();
    CURRENT.with(|current| *current.borrow_mut() = None);
    result
}
