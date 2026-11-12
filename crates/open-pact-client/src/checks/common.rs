use open_pact_core::ControlValue;

#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub(super) fn parse_groups(text: &str, admins: &[u32]) -> ControlValue {
    let groups: Result<Vec<u32>, _> = text.split_whitespace().map(str::parse).collect();
    match groups {
        Ok(groups) if !groups.is_empty() => {
            if groups.iter().any(|g| admins.contains(g)) {
                "admin"
            } else {
                "standard"
            }
        }
        _ => "unknown",
    }
    .into()
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub(super) fn bounded_age(age: i64, max: i32) -> ControlValue {
    if (0..=i64::from(max)).contains(&age) {
        (age as i32).into()
    } else {
        "unknown".into()
    }
}

pub fn not_applicable() -> ControlValue {
    "n/a".into()
}
pub fn unknown() -> ControlValue {
    "unknown".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_account_group_fixtures() {
        assert_eq!(parse_groups("20 80 12345\n", &[80]), "admin");
        assert_eq!(parse_groups("20 12\n", &[80]), "standard");
        // The unrelated GID can have a space or Unicode in its display name.
        assert_eq!(parse_groups("20 80 12345", &[80]), "admin");
        assert_eq!(parse_groups("20 12345", &[80]), "standard");
        assert_eq!(parse_groups("", &[80]), "unknown");
        assert_eq!(parse_groups("id: permission denied", &[80]), "unknown");
    }

    #[test]
    fn explicit_platform_sentinels() {
        assert_eq!(not_applicable(), "n/a");
    }
}
