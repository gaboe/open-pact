use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::exec::run_status;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Protection {
    On,
    Off,
    Unknown,
}

fn merge(states: &[Protection]) -> Protection {
    if states.contains(&Protection::Off) {
        Protection::Off
    } else if states.is_empty() || states.contains(&Protection::Unknown) {
        Protection::Unknown
    } else {
        Protection::On
    }
}

fn optional_json(path: &Path, plist: bool) -> Result<Value, ()> {
    match fs::metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Value::Object(Map::new())),
        Err(_) => return Err(()),
        Ok(_) => (),
    }
    let text = if plist {
        let path = path.to_str().ok_or(())?;
        run_status("/usr/bin/plutil", &["-convert", "json", "-o", "-", path])
            .filter(|r| r.success)
            .ok_or(())?
            .text
    } else {
        fs::read_to_string(path).map_err(|_| ())?
    };
    let json: Value = serde_json::from_str(&text).map_err(|_| ())?;
    if json.is_object() { Ok(json) } else { Err(()) }
}

fn flag(value: Option<&Value>) -> Protection {
    match value {
        None | Some(Value::Bool(true)) => Protection::On,
        Some(Value::Bool(false)) => Protection::Off,
        _ => Protection::Unknown,
    }
}

fn chromium(prefs: &Value, policy: &Value, recommended: &Value, edge: bool) -> Protection {
    let key = if edge {
        "SmartScreenEnabled"
    } else {
        "SafeBrowsingEnabled"
    };
    if !edge && let Some(level) = policy.get("SafeBrowsingProtectionLevel") {
        return protection_level(level);
    }
    if let Some(value) = policy.get(key) {
        return flag(Some(value));
    }
    let pointer = if edge {
        "/edge/smartscreen/enabled"
    } else {
        "/safebrowsing/enabled"
    };
    if let Some(value) = prefs.pointer(pointer) {
        return flag(Some(value));
    }
    if !edge && let Some(level) = recommended.get("SafeBrowsingProtectionLevel") {
        return protection_level(level);
    }
    Protection::On
}

fn protection_level(value: &Value) -> Protection {
    match value.as_i64() {
        Some(0) => Protection::Off,
        Some(1 | 2) => Protection::On,
        _ => Protection::Unknown,
    }
}

fn profiles(root: &Path, firefox: bool) -> Result<Vec<PathBuf>, ()> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(vec![]),
        Err(_) => return Err(()),
    };
    let canonical_root = root.canonicalize().map_err(|_| ())?;
    let mut found = vec![];
    for entry in entries {
        let entry = entry.map_err(|_| ())?;
        let kind = entry.file_type().map_err(|_| ())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let profile =
            firefox || name == "Default" || name.starts_with("Profile ") || name == "Guest Profile";
        if kind.is_symlink() {
            if profile {
                return Err(());
            }
            let path = entry.path();
            if path.join("Preferences").try_exists().map_err(|_| ())? {
                let target = path.canonicalize().map_err(|_| ())?;
                if !target.starts_with(&canonical_root) || !target.is_dir() {
                    return Err(());
                }
                found.push(path);
            }
            continue;
        }
        if !kind.is_dir() {
            continue;
        }
        if profile
            || entry
                .path()
                .join("Preferences")
                .try_exists()
                .map_err(|_| ())?
        {
            found.push(entry.path());
        }
    }
    Ok(found)
}

fn managed(domain: &str, home: &Path) -> Result<Value, ()> {
    let mut result = Map::new();
    let mut files = vec![PathBuf::from(format!(
        "/Library/Managed Preferences/{domain}.plist"
    ))];
    if let Some(user) = std::env::var_os("USER") {
        files.push(
            Path::new("/Library/Managed Preferences")
                .join(user)
                .join(format!("{domain}.plist")),
        );
    }
    files.push(home.join(format!("Library/Managed Preferences/{domain}.plist")));
    for path in files {
        let value = optional_json(&path, true)?;
        for (key, value) in value.as_object().ok_or(())? {
            if result.get(key).is_some_and(|old| old != value) {
                return Err(());
            }
            result.insert(key.clone(), value.clone());
        }
    }
    Ok(Value::Object(result))
}

fn recommended(domain: &str, home: &Path) -> Result<Value, ()> {
    let mut result = optional_json(
        &PathBuf::from(format!("/Library/Preferences/{domain}.plist")),
        true,
    )?;
    let user = optional_json(
        &home.join(format!("Library/Preferences/{domain}.plist")),
        true,
    )?;
    for (key, value) in user.as_object().ok_or(())? {
        result[key] = value.clone();
    }
    Ok(result)
}

fn chromium_browser(home: &Path, data: &str, domain: &str, edge: bool) -> Protection {
    let Ok(policy) = managed(domain, home) else {
        return Protection::Unknown;
    };
    let Ok(recommended) = recommended(domain, home) else {
        return Protection::Unknown;
    };
    let Ok(dirs) = profiles(&home.join("Library/Application Support").join(data), false) else {
        return Protection::Unknown;
    };
    if dirs.is_empty() {
        return chromium(&Value::Object(Map::new()), &policy, &recommended, edge);
    }
    let states: Vec<_> = dirs
        .iter()
        .map(|dir| {
            optional_json(&dir.join("Preferences"), false).map_or(Protection::Unknown, |v| {
                chromium(&v, &policy, &recommended, edge)
            })
        })
        .collect();
    merge(&states)
}

const FIREFOX_KEYS: &[&str] = &[
    "browser.safebrowsing.malware.enabled",
    "browser.safebrowsing.phishing.enabled",
];

fn firefox_prefs(text: &str) -> Result<Map<String, Value>, ()> {
    let mut prefs = Map::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with("//") || line.is_empty() {
            continue;
        }
        for key in FIREFOX_KEYS {
            let prefix = format!("user_pref(\"{key}\"");
            if line.starts_with(&prefix) {
                let rest = line[prefix.len()..]
                    .trim_start()
                    .strip_prefix(',')
                    .ok_or(())?
                    .trim();
                let value = rest.strip_suffix(");").ok_or(())?.trim();
                prefs.insert(
                    (*key).into(),
                    Value::Bool(match value {
                        "true" => true,
                        "false" => false,
                        _ => return Err(()),
                    }),
                );
            } else if line.contains(key) {
                return Err(());
            }
        }
    }
    Ok(prefs)
}

fn firefox_state(prefs: &Map<String, Value>, policy: &Value) -> Protection {
    let states: Vec<_> = FIREFOX_KEYS
        .iter()
        .map(|key| {
            let managed = policy
                .pointer("/policies/Preferences")
                .and_then(|p| p.get(*key));
            let value = match managed {
                Some(Value::Object(entry)) => {
                    let Some(value) = entry.get("Value") else {
                        return Protection::Unknown;
                    };
                    match entry
                        .get("Status")
                        .and_then(Value::as_str)
                        .unwrap_or("default")
                    {
                        "locked" => Some(value),
                        "user" => prefs.get(*key).or(Some(value)),
                        "default" => prefs.get(*key).or(Some(value)),
                        _ => return Protection::Unknown,
                    }
                }
                other => other.or_else(|| prefs.get(*key)),
            };
            firefox_flag(value)
        })
        .collect();
    merge(&states)
}

fn firefox_flag(value: Option<&Value>) -> Protection {
    match value.and_then(Value::as_i64) {
        Some(0) => Protection::Off,
        Some(1) => Protection::On,
        _ => flag(value),
    }
}

fn standard_firefox_profiles(ini: &str) -> bool {
    ini.lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("Path="))
        .all(|path| path.starts_with("Profiles/") && !path.split('/').any(|part| part == ".."))
}

fn firefox(home: &Path, app: &Path) -> Protection {
    match fs::read_to_string(home.join("Library/Application Support/Firefox/profiles.ini")) {
        Ok(ini) if !standard_firefox_profiles(&ini) => return Protection::Unknown,
        Err(e) if e.kind() != ErrorKind::NotFound => return Protection::Unknown,
        _ => (),
    }
    let Ok(mut policy) = optional_json(
        &app.join("Contents/Resources/distribution/policies.json"),
        false,
    ) else {
        return Protection::Unknown;
    };
    let Ok(plist_policy) = managed("org.mozilla.firefox", home) else {
        return Protection::Unknown;
    };
    if !plist_policy.as_object().is_some_and(Map::is_empty) {
        // Conflicting policy providers need the browser to resolve precedence.
        if policy.get("policies").is_some() {
            return Protection::Unknown;
        }
        policy = serde_json::json!({"policies": plist_policy});
    }
    let Ok(dirs) = profiles(
        &home.join("Library/Application Support/Firefox/Profiles"),
        true,
    ) else {
        return Protection::Unknown;
    };
    if dirs.is_empty() {
        return firefox_state(&Map::new(), &policy);
    }
    let states: Vec<_> = dirs
        .iter()
        .map(|dir| {
            let mut prefs = Map::new();
            for file in ["prefs.js", "user.js"] {
                let text = match fs::read_to_string(dir.join(file)) {
                    Ok(s) => s,
                    Err(e) if e.kind() == ErrorKind::NotFound => continue,
                    Err(_) => return Protection::Unknown,
                };
                let Ok(values) = firefox_prefs(&text) else {
                    return Protection::Unknown;
                };
                prefs.extend(values);
            }
            firefox_state(&prefs, &policy)
        })
        .collect();
    merge(&states)
}

fn web_protection(states: &[Protection]) -> &'static str {
    if states.is_empty() {
        return "n/a";
    }
    match merge(states) {
        Protection::On => "on",
        Protection::Off => "off",
        Protection::Unknown => "unknown",
    }
}

pub fn macos() -> &'static str {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return "unknown";
    };
    let mut states = vec![];
    for (name, data, domain, edge) in [
        ("Google Chrome", "Google/Chrome", "com.google.Chrome", false),
        (
            "Microsoft Edge",
            "Microsoft Edge",
            "com.microsoft.Edge",
            true,
        ),
        (
            "Brave Browser",
            "BraveSoftware/Brave-Browser",
            "com.brave.Browser",
            false,
        ),
        ("Firefox", "", "", false),
    ] {
        let candidates = [
            PathBuf::from(format!("/Applications/{name}.app")),
            home.join(format!("Applications/{name}.app")),
            PathBuf::from(format!("/System/Applications/{name}.app")),
        ];
        for app in candidates {
            match fs::metadata(&app) {
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(_) => {
                    states.push(Protection::Unknown);
                    continue;
                }
                Ok(_) => (),
            }
            let state = if name == "Firefox" {
                firefox(&home, &app)
            } else {
                chromium_browser(&home, data, domain, edge)
            };
            if state == Protection::Unknown {
                eprintln!("web_protection: {name} settings are unreadable or unsupported");
            }
            states.push(state);
        }
    }
    web_protection(&states)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn chromium_defaults_and_policy_precedence() {
        assert_eq!(
            chromium(&json!({}), &json!({}), &json!({}), false),
            Protection::On
        );
        let off = json!({"safebrowsing":{"enabled":false}});
        assert_eq!(
            chromium(&off, &json!({}), &json!({}), false),
            Protection::Off
        );
        assert_eq!(
            chromium(
                &off,
                &json!({"SafeBrowsingEnabled":true}),
                &json!({}),
                false
            ),
            Protection::On
        );
        assert_eq!(
            chromium(
                &json!({}),
                &json!({"SafeBrowsingEnabled":true,"SafeBrowsingProtectionLevel":0}),
                &json!({}),
                false
            ),
            Protection::Off
        );
        assert_eq!(
            chromium(
                &json!({}),
                &json!({"SafeBrowsingProtectionLevel":3}),
                &json!({}),
                false
            ),
            Protection::Unknown
        );
        assert_eq!(
            chromium(
                &json!({"edge":{"smartscreen":{"enabled":false}}}),
                &json!({}),
                &json!({}),
                true
            ),
            Protection::Off
        );
    }
    #[test]
    fn firefox_defaults_overrides_and_malformed_values() {
        let text = "// Mozilla User Preferences\nuser_pref(\"browser.safebrowsing.malware.enabled\", false);\nuser_pref(\"browser.safebrowsing.phishing.enabled\", true);\n";
        let prefs = firefox_prefs(text).unwrap();
        assert_eq!(firefox_state(&Map::new(), &json!({})), Protection::On);
        assert_eq!(firefox_state(&prefs, &json!({})), Protection::Off);
        assert_eq!(
            firefox_state(
                &prefs,
                &json!({"policies":{"Preferences":{"browser.safebrowsing.malware.enabled":{"Value":true,"Status":"locked"}}}})
            ),
            Protection::On
        );
        assert!(firefox_prefs("user_pref(\"browser.safebrowsing.malware.enabled\", 0);").is_err());
    }
    #[test]
    fn every_browser_must_be_known_and_on() {
        assert_eq!(merge(&[Protection::On, Protection::Off]), Protection::Off);
        assert_eq!(
            merge(&[Protection::On, Protection::Unknown]),
            Protection::Unknown
        );
        assert_eq!(
            merge(&[Protection::Off, Protection::Unknown]),
            Protection::Off
        );
        assert_eq!(merge(&[]), Protection::Unknown);
        assert_eq!(flag(Some(&json!("false"))), Protection::Unknown);
    }

    #[test]
    fn safari_only_is_not_applicable() {
        assert_eq!(web_protection(&[]), "n/a");
    }

    #[test]
    fn safari_and_chrome_on_is_on() {
        assert_eq!(web_protection(&[Protection::On]), "on");
    }

    #[test]
    fn safari_and_firefox_off_is_off() {
        assert_eq!(web_protection(&[Protection::Off]), "off");
    }
    #[test]
    fn managed_defaults_do_not_hide_a_disabled_firefox_preference() {
        let prefs =
            firefox_prefs("user_pref(\"browser.safebrowsing.malware.enabled\", false);").unwrap();
        assert_eq!(
            firefox_state(
                &prefs,
                &json!({"policies":{"Preferences":{"browser.safebrowsing.malware.enabled":{"Value":true,"Status":"default"}}}})
            ),
            Protection::Off
        );
        assert_eq!(
            firefox_state(
                &Map::new(),
                &json!({"policies":{"Preferences":{"browser.safebrowsing.malware.enabled":{"Status":"locked"}}}})
            ),
            Protection::Unknown
        );
        assert!(standard_firefox_profiles(
            "[Profile0]\nPath=Profiles/fictional.default\n"
        ));
        assert!(!standard_firefox_profiles(
            "[Profile0]\nPath=/fictional/external\nIsRelative=0\n"
        ));
    }

    #[test]
    fn user_firefox_policy_does_not_hide_current_disabled_preference() {
        let prefs =
            firefox_prefs("user_pref(\"browser.safebrowsing.malware.enabled\", false);").unwrap();
        let policy = json!({"policies":{"Preferences":{"browser.safebrowsing.malware.enabled":{"Value":true,"Status":"user"}}}});
        assert_eq!(firefox_state(&prefs, &policy), Protection::Off);
    }

    #[test]
    fn numeric_firefox_policy_values_are_booleans() {
        let actual: Vec<_> = [0, 1]
            .into_iter()
            .map(|value| {
                let policy = json!({"policies":{"Preferences":{"browser.safebrowsing.malware.enabled":{"Value":value,"Status":"locked"}}}});
                firefox_state(&Map::new(), &policy)
            })
            .collect();
        assert_eq!(actual, vec![Protection::Off, Protection::On]);
    }

    #[test]
    fn file_reader_distinguishes_absence_from_unreadable_or_malformed() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            optional_json(&root.path().join("missing"), false).unwrap(),
            json!({})
        );
        assert!(optional_json(root.path(), false).is_err());
        let file = root.path().join("Preferences");
        fs::write(&file, "{truncated").unwrap();
        assert!(optional_json(&file, false).is_err());
        fs::write(&file, r#"{"safebrowsing":{"enabled":false}}"#).unwrap();
        assert_eq!(
            chromium(
                &optional_json(&file, false).unwrap(),
                &json!({}),
                &json!({}),
                false
            ),
            Protection::Off
        );
    }
    #[test]
    #[cfg(unix)]
    fn chrome_lock_symlinks_are_not_profiles() {
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("fictional-cookie", root.path().join("SingletonCookie"))
            .unwrap();
        let profile = root.path().join("Default");
        fs::create_dir(&profile).unwrap();
        fs::write(
            profile.join("Preferences"),
            r#"{"safebrowsing":{"enabled":false}}"#,
        )
        .unwrap();
        assert_eq!(profiles(root.path(), false).unwrap(), vec![profile.clone()]);
        std::os::unix::fs::symlink(&profile, root.path().join("Profile 1")).unwrap();
        assert!(profiles(root.path(), false).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn custom_profile_symlink_inside_data_root_is_discovered() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("FictionalStorage/Custom");
        fs::create_dir_all(&target).unwrap();
        fs::write(
            target.join("Preferences"),
            r#"{"safebrowsing":{"enabled":false}}"#,
        )
        .unwrap();
        let link = root.path().join("Custom");
        std::os::unix::fs::symlink("FictionalStorage/Custom", &link).unwrap();
        assert_eq!(profiles(root.path(), false).unwrap(), vec![link]);
    }

    #[test]
    fn chromium_recommended_policy_applies_below_user_preferences() {
        let home = tempfile::tempdir().unwrap();
        let prefs_dir = home.path().join("Library/Preferences");
        fs::create_dir_all(&prefs_dir).unwrap();
        fs::write(
            prefs_dir.join("org.openpact.fictional-browser.plist"),
            "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>SafeBrowsingProtectionLevel</key><integer>0</integer></dict></plist>",
        )
        .unwrap();
        assert_eq!(
            chromium_browser(
                home.path(),
                "FictionalBrowser",
                "org.openpact.fictional-browser",
                false,
            ),
            Protection::Off
        );

        let profile = home
            .path()
            .join("Library/Application Support/FictionalBrowser/Default");
        fs::create_dir_all(&profile).unwrap();
        fs::write(
            profile.join("Preferences"),
            r#"{"safebrowsing":{"enabled":true}}"#,
        )
        .unwrap();
        assert_eq!(
            chromium_browser(
                home.path(),
                "FictionalBrowser",
                "org.openpact.fictional-browser",
                false,
            ),
            Protection::On
        );
    }
}
