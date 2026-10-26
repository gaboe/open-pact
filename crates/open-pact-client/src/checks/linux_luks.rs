use std::collections::BTreeSet;

use open_pact_core::ControlValue;
use serde::Deserialize;
use serde_json::Value;

use super::exec::run_status;

#[derive(Deserialize)]
struct BlockTree {
    blockdevices: Vec<BlockDevice>,
}

#[derive(Deserialize)]
struct BlockDevice {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    fstype: Option<String>,
    mountpoints: Vec<Option<String>>,
    #[serde(default)]
    children: Vec<BlockDevice>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Unlock {
    None,
    Hardware,
    Secret,
    Unknown,
}

impl Unlock {
    fn value(self) -> ControlValue {
        match self {
            Self::None => "none",
            Self::Hardware => "hardware_only",
            Self::Secret => "user_secret",
            Self::Unknown => "unknown",
        }
        .into()
    }
}

pub fn preboot_auth() -> ControlValue {
    let Some(output) = run_status(
        "lsblk",
        &[
            "--json",
            "--inverse",
            "--paths",
            "--output",
            "NAME,TYPE,FSTYPE,MOUNTPOINTS",
        ],
    )
    .filter(|r| r.success) else {
        return Unlock::Unknown.value();
    };
    let crypttab = std::fs::read_to_string("/etc/crypttab").ok();
    inspect_tree(&output.text, |device, mapping| {
        let Some(crypttab) = crypttab.as_deref() else {
            return Unlock::Unknown;
        };
        let boot = parse_crypttab(crypttab, mapping);
        let metadata = run_status("cryptsetup", &["luksDump", "--dump-json-metadata", device])
            .filter(|r| r.success)
            .and_then(|r| metadata_unlock(&r.text));
        boot.unlock(metadata)
    })
    .value()
}

fn inspect_tree(text: &str, mut inspect: impl FnMut(&str, &str) -> Unlock) -> Unlock {
    let Ok(tree) = serde_json::from_str::<BlockTree>(text) else {
        return Unlock::Unknown;
    };
    let mut root = false;
    let mut states = Vec::new();
    for device in &tree.blockdevices {
        let is_root = device.mountpoints.iter().any(|m| m.as_deref() == Some("/"));
        let is_swap = device
            .mountpoints
            .iter()
            .any(|m| m.as_deref() == Some("[SWAP]"));
        if !is_root && (!is_swap || device.name.starts_with("/dev/zram")) {
            continue;
        }
        root |= is_root;
        states.push(inspect_device(device, None, &mut inspect));
    }
    if !root || states.contains(&Unlock::Unknown) {
        Unlock::Unknown
    } else if states.contains(&Unlock::None) {
        Unlock::None
    } else if states.contains(&Unlock::Hardware) {
        Unlock::Hardware
    } else {
        Unlock::Secret
    }
}

fn inspect_device(
    device: &BlockDevice,
    mapping: Option<&str>,
    inspect: &mut impl FnMut(&str, &str) -> Unlock,
) -> Unlock {
    let mapping = if device.kind == "crypt" {
        device.name.rsplit('/').next()
    } else {
        mapping
    };
    if device.fstype.as_deref() == Some("crypto_LUKS") {
        return mapping.map_or(Unlock::Unknown, |mapping| inspect(&device.name, mapping));
    }
    if device.children.is_empty() {
        return match device.kind.as_str() {
            "disk" | "part" | "loop" => Unlock::None,
            _ => Unlock::Unknown,
        };
    }
    let states: Vec<_> = device
        .children
        .iter()
        .map(|d| inspect_device(d, mapping, inspect))
        .collect();
    if states.contains(&Unlock::Unknown) {
        Unlock::Unknown
    } else if states.contains(&Unlock::None) {
        Unlock::None
    } else if states.contains(&Unlock::Hardware) {
        Unlock::Hardware
    } else {
        Unlock::Secret
    }
}

#[derive(Debug, Eq, PartialEq)]
enum BootKey<'a> {
    Secret,
    Hardware,
    File(&'a str),
    Unknown,
}

impl BootKey<'_> {
    fn unlock(self, metadata: Option<Unlock>) -> Unlock {
        match self {
            Self::Unknown => Unlock::Unknown,
            Self::Secret => metadata.unwrap_or(Unlock::Secret),
            Self::Hardware => metadata.unwrap_or(Unlock::Hardware),
            Self::File(path) => keyfile_unlock(path),
        }
    }
}

fn parse_crypttab<'a>(text: &'a str, mapping: &str) -> BootKey<'a> {
    let mut entries = text
        .lines()
        .map(|line| {
            line.split('#')
                .next()
                .unwrap_or("")
                .split_whitespace()
                .collect::<Vec<_>>()
        })
        .filter(|fields| fields.first() == Some(&mapping));
    let Some(fields) = entries.next() else {
        return BootKey::Unknown;
    };
    if entries.next().is_some() || fields.len() < 2 || fields.len() > 4 {
        return BootKey::Unknown;
    }
    let key = fields.get(2).copied().unwrap_or("none");
    let options = fields.get(3).copied().unwrap_or("");
    if options.split(',').any(|o| o == "try-empty-password=yes") {
        return BootKey::Unknown;
    }
    let pin = options
        .split(',')
        .any(|o| matches!(o, "tpm2-pin=yes" | "fido2-pin=yes"));
    if options
        .split(',')
        .any(|o| o.starts_with("tpm2-device=") || o.starts_with("fido2-device=") || o == "clevis")
    {
        if pin {
            BootKey::Secret
        } else {
            BootKey::Hardware
        }
    } else if matches!(key, "none" | "-") {
        BootKey::Unknown
    } else if key.starts_with('/') && !key.contains('\\') {
        BootKey::File(key)
    } else {
        BootKey::Unknown
    }
}

fn keyfile_unlock(path: &str) -> Unlock {
    if !std::path::Path::new(path).is_file() {
        return Unlock::Unknown;
    }
    let Some(source) = run_status(
        "findmnt",
        &["--noheadings", "--output", "SOURCE", "--target", path],
    )
    .filter(|r| r.success) else {
        return Unlock::Unknown;
    };
    let Some(tree) = run_status(
        "lsblk",
        &[
            "--inverse",
            "--noheadings",
            "--output",
            "TYPE,FSTYPE",
            source.text.trim(),
        ],
    )
    .filter(|r| r.success) else {
        return Unlock::Unknown;
    };
    if tree.text.lines().any(|line| {
        line.split_whitespace()
            .any(|field| field == "crypt" || field == "crypto_LUKS")
    }) {
        Unlock::Unknown
    } else if tree
        .text
        .split_whitespace()
        .any(|field| matches!(field, "disk" | "part" | "loop"))
    {
        Unlock::None
    } else {
        Unlock::Unknown
    }
}

fn metadata_unlock(text: &str) -> Option<Unlock> {
    if let Ok(metadata) = serde_json::from_str::<Value>(text)
        && metadata
            .get("keyslots")
            .and_then(Value::as_object)
            .is_some_and(|s| !s.is_empty())
        && metadata
            .get("tokens")
            .and_then(Value::as_object)
            .is_some_and(|t| t.is_empty())
    {
        return None;
    }
    Some(parse_metadata(text))
}

fn parse_metadata(text: &str) -> Unlock {
    let Ok(metadata) = serde_json::from_str::<Value>(text) else {
        return Unlock::Unknown;
    };
    let Some(slots) = metadata
        .get("keyslots")
        .and_then(Value::as_object)
        .filter(|s| !s.is_empty())
    else {
        return Unlock::Unknown;
    };
    let Some(tokens) = metadata.get("tokens").and_then(Value::as_object) else {
        return Unlock::Unknown;
    };
    let mut covered = BTreeSet::new();
    let mut hardware = false;
    for token in tokens.values() {
        let pin = match token.get("type").and_then(Value::as_str) {
            Some("systemd-tpm2") => token.get("tpm2-pin"),
            Some("systemd-fido2") => token.get("fido2-clientPin-required"),
            Some("clevis") => None,
            _ => return Unlock::Unknown,
        };
        let pin = match pin {
            Some(Value::Bool(pin)) => *pin,
            None => false,
            _ => return Unlock::Unknown,
        };
        let Some(bound) = token
            .get("keyslots")
            .and_then(Value::as_array)
            .filter(|s| !s.is_empty())
        else {
            return Unlock::Unknown;
        };
        for slot in bound {
            let Some(slot) = slot.as_str().filter(|s| slots.contains_key(*s)) else {
                return Unlock::Unknown;
            };
            covered.insert(slot);
        }
        hardware |= !pin;
    }
    // A tokenless slot can contain a passphrase, a recovery key, or an on-disk keyfile.
    if hardware {
        Unlock::Hardware
    } else if covered.len() != slots.len() {
        Unlock::Unknown
    } else {
        Unlock::Secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unlock_requires_all_slots_to_have_known_token_metadata() {
        let metadata = |tokens: Value| json!({"keyslots":{"0":{}},"tokens":tokens}).to_string();
        for (token, expected) in [
            (
                json!({"type":"systemd-tpm2","keyslots":["0"],"tpm2-pin":false}),
                Unlock::Hardware,
            ),
            (
                json!({"type":"systemd-tpm2","keyslots":["0"],"tpm2-pin":true}),
                Unlock::Secret,
            ),
            (
                json!({"type":"systemd-fido2","keyslots":["0"],"fido2-clientPin-required":true}),
                Unlock::Secret,
            ),
            (
                json!({"type":"systemd-fido2","keyslots":["0"]}),
                Unlock::Hardware,
            ),
            (json!({"type":"clevis","keyslots":["0"]}), Unlock::Hardware),
            (
                json!({"type":"systemd-tpm2","keyslots":["1"]}),
                Unlock::Unknown,
            ),
        ] {
            assert_eq!(parse_metadata(&metadata(json!({"0":token}))), expected);
        }
        assert_eq!(parse_metadata(&metadata(json!({}))), Unlock::Unknown);
        assert_eq!(parse_metadata("permission denied"), Unlock::Unknown);
        assert_eq!(
            parse_metadata(r#"{"keyslots":{},"tokens":{}}"#),
            Unlock::Unknown
        );
    }

    #[test]
    fn root_and_swap_follow_only_their_inverse_block_branches() {
        let disk = json!({"name":"/dev/fictional","type":"part","fstype":"crypto_LUKS","mountpoints":[null]});
        let root = json!({"name":"/dev/mapper/root","type":"crypt","fstype":"ext4","mountpoints":["/"],"children":[disk]});
        let zram =
            json!({"name":"/dev/zram0","type":"disk","fstype":"swap","mountpoints":["[SWAP]"]});
        assert_eq!(
            inspect_tree(&json!({"blockdevices":[root,zram]}).to_string(), |_, _| {
                Unlock::Secret
            }),
            Unlock::Secret
        );
        let plain_swap = json!({"name":"/dev/fictional-swap","type":"part","fstype":"swap","mountpoints":["[SWAP]"]});
        assert_eq!(
            inspect_tree(&json!({"blockdevices":[root]}).to_string(), |_, _| {
                Unlock::Hardware
            }),
            Unlock::Hardware
        );
        assert_eq!(
            inspect_tree(
                &json!({"blockdevices":[root,plain_swap]}).to_string(),
                |_, _| Unlock::Hardware
            ),
            Unlock::None
        );
        assert_eq!(
            inspect_tree(&json!({"blockdevices":[root]}).to_string(), |_, _| {
                Unlock::Unknown
            }),
            Unlock::Unknown
        );
        assert_eq!(
            inspect_tree(r#"{"blockdevices":[]}"#, |_, _| Unlock::Secret),
            Unlock::Unknown
        );
    }
}

#[cfg(test)]
mod crypttab_tests {
    use super::*;
    #[test]
    fn automatic_sources_do_not_establish_a_required_secret() {
        assert_eq!(
            parse_crypttab("root UUID=fictional none try-empty-password=yes", "root"),
            BootKey::Unknown
        );
        assert_eq!(
            parse_crypttab("root UUID=fictional none luks", "root"),
            BootKey::Unknown
        );
        assert_eq!(
            parse_crypttab("root UUID=fictional none luks", "root").unlock(None),
            Unlock::Unknown
        );
    }

    #[test]
    fn boolean_aliases_and_pin_sources_are_device_specific() {
        for value in ["1", "yes", "y", "true", "t", "on", "TRUE", "Y"] {
            for source in [
                "tpm2-device=auto,tpm2-pin",
                "fido2-cid=ZmljdGlvbmFs,fido2-pin",
            ] {
                let line = format!("root UUID=fictional /fictional/salt {source}={value}");
                assert_eq!(
                    parse_crypttab(&line, "root").unlock(None),
                    Unlock::Secret,
                    "{line}"
                );
                let automatic = format!("{line},try-empty-password={value}");
                assert_eq!(
                    parse_crypttab(&automatic, "root").unlock(None),
                    Unlock::Unknown,
                    "{automatic}"
                );
            }
        }
        for value in ["0", "no", "n", "false", "f", "off", "FALSE", "N"] {
            let line = format!(
                "root UUID=fictional - tpm2-device=auto,tpm2-pin={value},try-empty-password={value}"
            );
            assert_eq!(
                parse_crypttab(&line, "root").unlock(None),
                Unlock::Hardware,
                "{line}"
            );
        }
        for options in [
            "tpm2-device=auto,fido2-pin=yes",
            "fido2-cid=ZmljdGlvbmFs,tpm2-pin=yes",
            "fido2-device=auto,fido2-pin=yes",
        ] {
            let line = format!("root UUID=fictional - {options}");
            assert_eq!(
                parse_crypttab(&line, "root").unlock(None),
                Unlock::Hardware,
                "{line}"
            );
        }
    }

    #[test]
    fn manual_hardware_pin_is_a_secret() {
        for options in [
            "tpm2-device=auto,tpm2-pin=yes",
            "fido2-device=auto,fido2-cid=fictional,fido2-pin=yes",
        ] {
            assert_eq!(
                parse_crypttab(&format!("root UUID=fictional - {options}"), "root"),
                BootKey::Secret
            );
            assert_eq!(
                parse_crypttab(&format!("root UUID=fictional - {options}"), "root")
                    .unlock(metadata_unlock(r#"{"keyslots":{"0":{}},"tokens":{}}"#)),
                Unlock::Secret
            );
        }
    }

    #[test]
    fn boot_mapping_distinguishes_prompts_hardware_and_keyfiles() {
        for (line, expected) in [
            ("root UUID=fictional none luks", BootKey::Unknown),
            ("root UUID=fictional - luks", BootKey::Unknown),
            ("root UUID=fictional", BootKey::Unknown),
            (
                "root UUID=fictional none tpm2-device=auto",
                BootKey::Hardware,
            ),
            ("root UUID=fictional - fido2-device=auto", BootKey::Hardware),
            ("root UUID=fictional none clevis", BootKey::Hardware),
            (
                "root UUID=fictional /fictional/key luks",
                BootKey::File("/fictional/key"),
            ),
            ("other UUID=fictional none luks", BootKey::Unknown),
            ("# root UUID=fictional none luks", BootKey::Unknown),
            (
                "root UUID=fictional none luks\nroot UUID=other -",
                BootKey::Unknown,
            ),
        ] {
            assert_eq!(parse_crypttab(line, "root"), expected);
        }
    }
}
