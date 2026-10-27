use super::*;
use crate::checks::contracts::Case;
use open_pact_core::ControlValue;

pub(crate) fn run(id: &str, case: &Case) -> ControlValue {
    assert_eq!(id, "web_protection");
    let states: Vec<_> = case
        .input
        .iter()
        .map(|input| match input {
            None => Protection::Unknown,
            Some(text) => {
                let value: serde_json::Value =
                    serde_json::from_str(text).expect("browser fixture JSON");
                windows_browser(&value)
            }
        })
        .collect();
    web_protection(&states).into()
}
