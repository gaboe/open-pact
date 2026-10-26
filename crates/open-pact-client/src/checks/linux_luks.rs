use std::collections::{BTreeMap, BTreeSet};

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
    uuid: Option<String>,
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
            "NAME,TYPE,FSTYPE,UUID,MOUNTPOINTS",
        ],
    )
    .filter(|r| r.success) else {
        return Unlock::Unknown.value();
    };
    let crypttab = match std::fs::read_to_string("/etc/crypttab") {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        result => result,
    };
    let cmdline = std::fs::read_to_string("/proc/cmdline");
    let uuids = device_uuids(&output.text);
    let config =
        crypttab
            .as_deref()
            .ok()
            .zip(cmdline.as_deref().ok())
            .map(|(crypttab, cmdline)| {
                BootConfig::parse_bound(crypttab, cmdline, |mapping| {
                    uuids.get(mapping).map(String::as_str)
                })
            });
    inspect_tree(&output.text, |device, mapping| {
        let Some(config) = &config else {
            return Unlock::Unknown;
        };
        let boot = config.key(mapping);
        let metadata = run_status("cryptsetup", &["luksDump", "--dump-json-metadata", device])
            .filter(|r| r.success)
            .and_then(|r| metadata_unlock(&r.text));
        boot.unlock(metadata)
    })
    .value()
}

fn device_uuids(text: &str) -> BTreeMap<String, String> {
    fn collect(device: &BlockDevice, mapping: Option<&str>, uuids: &mut BTreeMap<String, String>) {
        let mapping = if device.kind == "crypt" {
            device.name.rsplit('/').next()
        } else {
            mapping
        };
        if device.fstype.as_deref() == Some("crypto_LUKS")
            && let (Some(mapping), Some(uuid)) = (mapping, device.uuid.as_ref())
        {
            uuids.insert(mapping.to_owned(), uuid.clone());
        }
        for child in &device.children {
            collect(child, mapping, uuids);
        }
    }
    let mut uuids = BTreeMap::new();
    if let Ok(tree) = serde_json::from_str::<BlockTree>(text) {
        for device in &tree.blockdevices {
            collect(device, None, &mut uuids);
        }
    }
    uuids
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HardwareSource {
    Tpm2,
    Fido2,
    Clevis,
}

#[derive(Debug)]
struct HardwareKey {
    source: HardwareSource,
    pin: bool,
}

#[derive(Debug)]
struct UnlockOptions {
    hardware: Vec<HardwareKey>,
    try_empty_password: bool,
}

fn systemd_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Some(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Some(false),
        _ => None,
    }
}

impl UnlockOptions {
    fn parse(text: &str) -> Option<Self> {
        let (mut tpm2, mut fido2, mut cid, mut clevis) = (false, false, false, false);
        let (mut tpm2_pin, mut fido2_pin, mut try_empty_password) = (false, false, false);
        for option in text.split(',') {
            let (name, value) = option.split_once('=').unwrap_or((option, ""));
            match name {
                "tpm2-device" => tpm2 = !value.is_empty(),
                "fido2-device" => fido2 = !value.is_empty(),
                "fido2-cid" => cid = !value.is_empty(),
                "clevis" => clevis = true,
                "tpm2-pin" => tpm2_pin = systemd_bool(value)?,
                "fido2-pin" => fido2_pin = systemd_bool(value)?,
                "try-empty-password" => try_empty_password = systemd_bool(value)?,
                _ => (),
            }
        }
        let hardware = [
            (HardwareSource::Tpm2, tpm2, tpm2_pin),
            (HardwareSource::Fido2, fido2 || cid, cid && fido2_pin),
            (HardwareSource::Clevis, clevis, false),
        ]
        .into_iter()
        .filter_map(|(source, enabled, pin)| enabled.then_some(HardwareKey { source, pin }))
        .collect();
        Some(Self {
            hardware,
            try_empty_password,
        })
    }

    fn key<'a>(&self, keyfile: &'a str) -> BootKey<'a> {
        if self.try_empty_password {
            BootKey::Unknown
        } else if !self.hardware.is_empty() {
            if self.hardware.iter().all(|key| match key.source {
                HardwareSource::Tpm2 | HardwareSource::Fido2 => key.pin,
                HardwareSource::Clevis => false,
            }) {
                BootKey::Secret
            } else {
                BootKey::Hardware
            }
        } else if keyfile.starts_with('/') && !keyfile.contains('\\') {
            BootKey::File(keyfile)
        } else {
            BootKey::Unknown
        }
    }
}

struct BootEntry<'a> {
    mapping: String,
    uuid: Option<&'a str>,
    keyfile: &'a str,
    options: &'a str,
    valid: bool,
    from_crypttab: bool,
}

struct BootDevice<'a> {
    mapping: String,
    uuid: Option<&'a str>,
    keyfile: &'a str,
    options: Option<UnlockOptions>,
}

struct BootConfig<'a> {
    devices: Vec<BootDevice<'a>>,
}

impl<'a> BootConfig<'a> {
    #[cfg(test)]
    fn parse(crypttab: &'a str, cmdline: &'a str) -> Self {
        Self::parse_bound(crypttab, cmdline, |_| None)
    }

    fn parse_bound(
        crypttab: &'a str,
        cmdline: &'a str,
        uuid: impl Fn(&str) -> Option<&'a str>,
    ) -> Self {
        if cmdline.split_whitespace().any(|word| {
            word.contains("luks")
                && (word.matches('"').count() % 2 != 0 || word.matches('\'').count() % 2 != 0)
        }) {
            return Self {
                devices: Vec::new(),
            };
        }
        let parameters: Vec<_> = cmdline
            .split_whitespace()
            .filter_map(|word| {
                let word = word.trim_matches(['"', '\'']);
                let word = word.strip_prefix("rd.").unwrap_or(word);
                let (name, value) = word.split_once('=')?;
                let name = if name == "luks" {
                    ""
                } else {
                    name.strip_prefix("luks.")?
                };
                Some((name, value.trim_matches(['"', '\''])))
            })
            .collect();
        if parameters
            .iter()
            .any(|(name, value)| name.is_empty() && systemd_bool(value) != Some(true))
        {
            return Self {
                devices: Vec::new(),
            };
        }
        let use_crypttab = parameters
            .iter()
            .rfind(|(name, _)| *name == "crypttab")
            .is_none_or(|(_, value)| systemd_bool(value) == Some(true));
        let mut entries = Vec::new();
        for line in crypttab.lines().filter(|_| use_crypttab) {
            let fields: Vec<_> = line
                .split('#')
                .next()
                .unwrap_or("")
                .split_whitespace()
                .collect();
            if fields.is_empty() {
                continue;
            }
            entries.push(BootEntry {
                mapping: fields[0].to_owned(),
                uuid: fields
                    .get(1)
                    .and_then(|s| s.strip_prefix("UUID="))
                    .or_else(|| uuid(fields[0])),
                keyfile: fields.get(2).copied().unwrap_or("none"),
                options: fields.get(3).copied().unwrap_or(""),
                valid: (2..=4).contains(&fields.len()),
                from_crypttab: true,
            });
        }
        for (name, value) in &parameters {
            let binding = match *name {
                "uuid" => Some((*value, None)),
                "name" => value
                    .split_once('=')
                    .map(|(uuid, mapping)| (uuid, Some(mapping))),
                _ => None,
            };
            if let Some((uuid, mapping)) = binding {
                if let Some(entry) = entries.iter_mut().find(|entry| {
                    entry
                        .uuid
                        .is_some_and(|bound| bound.eq_ignore_ascii_case(uuid))
                }) {
                    if let Some(mapping) = mapping {
                        entry.mapping = mapping.to_owned();
                    }
                } else {
                    entries.push(BootEntry {
                        mapping: mapping
                            .map(str::to_owned)
                            .unwrap_or_else(|| format!("luks-{uuid}")),
                        uuid: Some(uuid),
                        keyfile: "none",
                        options: "",
                        valid: true,
                        from_crypttab: false,
                    });
                }
            }
        }
        let devices = entries
            .into_iter()
            .map(
                |BootEntry {
                     mapping,
                     uuid,
                     mut keyfile,
                     mut options,
                     valid,
                     from_crypttab,
                 }| {
                    for name in ["options", "key"] {
                        let bound = parameters
                            .iter()
                            .filter(|(n, _)| *n == name)
                            .filter_map(|(_, value)| {
                                let (binding, value) = value.split_once('=')?;
                                uuid.filter(|uuid| uuid.eq_ignore_ascii_case(binding))
                                    .map(|_| value)
                            })
                            .next_back();
                        let default = parameters
                            .iter()
                            .filter(|(n, _)| *n == name)
                            .map(|(_, value)| *value)
                            .rfind(|value| {
                                !value
                                    .split_once('=')
                                    .is_some_and(|(prefix, _)| is_uuid(prefix))
                            });
                        if let Some(value) = bound.or(if name == "key" || !from_crypttab {
                            default
                        } else {
                            None
                        }) {
                            if name == "options" {
                                options = value;
                            } else {
                                keyfile = value;
                            }
                        }
                    }
                    let binding_known = uuid.is_some()
                        || !parameters.iter().any(|(name, value)| {
                            matches!(*name, "key" | "options")
                                && value
                                    .split_once('=')
                                    .is_some_and(|(prefix, _)| is_uuid(prefix))
                        });
                    BootDevice {
                        mapping,
                        uuid,
                        keyfile,
                        options: if valid && binding_known {
                            UnlockOptions::parse(options)
                        } else {
                            None
                        },
                    }
                },
            )
            .collect();
        Self { devices }
    }

    fn key(&self, mapping: &str) -> BootKey<'a> {
        let mut devices = self.devices.iter().filter(|device| {
            device.mapping == mapping
                || device.uuid.is_some_and(|uuid| {
                    mapping
                        .strip_prefix("luks-")
                        .is_some_and(|bound| bound.eq_ignore_ascii_case(uuid))
                })
        });
        let Some(device) = devices.next() else {
            return BootKey::Unknown;
        };
        if devices.next().is_some() {
            return BootKey::Unknown;
        }
        device
            .options
            .as_ref()
            .map_or(BootKey::Unknown, |options| options.key(device.keyfile))
    }
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, byte)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
fn parse_crypttab<'a>(text: &'a str, mapping: &str) -> BootKey<'a> {
    BootConfig::parse(text, "").key(mapping)
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
    fn path_entries_bind_kernel_options_by_block_device_uuid() {
        let uuid = "11111111-1111-1111-1111-111111111111";
        let tree = serde_json::json!({"blockdevices":[{
            "name":"/dev/mapper/root", "type":"crypt", "fstype":"ext4", "mountpoints":["/"],
            "children":[{"name":"/dev/fictional", "type":"part", "fstype":"crypto_LUKS", "uuid":uuid, "mountpoints":[null]}]
        }]}).to_string();
        let uuids = device_uuids(&tree);
        assert_eq!(uuids.get("root").map(String::as_str), Some(uuid));
        let cmdline =
            format!("rd.luks.options={uuid}=tpm2-device=auto,tpm2-pin=true,try-empty-password=on");
        let config = BootConfig::parse_bound(
            "root /dev/fictional - tpm2-device=auto,tpm2-pin=yes",
            &cmdline,
            |mapping| uuids.get(mapping).map(String::as_str),
        );
        assert_eq!(config.key("root"), BootKey::Unknown);
    }

    #[test]
    fn kernel_unlock_options_keep_uuid_and_pin_bindings() {
        let root_uuid = "11111111-1111-1111-1111-111111111111";
        let swap_uuid = "22222222-2222-2222-2222-222222222222";
        let crypttab = format!(
            "root UUID={root_uuid} - tpm2-device=auto\nswap UUID={swap_uuid} - tpm2-device=auto"
        );
        for prefix in ["luks", "rd.luks"] {
            for value in ["1", "yes", "y", "true", "t", "on", "TRUE"] {
                let cmdline = format!(
                    "{prefix}.options={root_uuid}=fido2-cid=ZmljdGlvbmFs,fido2-pin={value} {prefix}.options={swap_uuid}=tpm2-device=auto,fido2-pin={value}"
                );
                let config = BootConfig::parse(&crypttab, &cmdline);
                assert_eq!(config.key("root").unlock(None), Unlock::Secret);
                assert_eq!(config.key("swap").unlock(None), Unlock::Hardware);
                let cmdline = format!(
                    "{prefix}.options={root_uuid}=tpm2-device=auto,tpm2-pin={value},try-empty-password={value}"
                );
                assert_eq!(
                    BootConfig::parse(&crypttab, &cmdline).key("root"),
                    BootKey::Unknown
                );
            }
            let cmdline = format!(
                "{prefix}.uuid={root_uuid} {prefix}.options=fido2-cid=ZmljdGlvbmFs,fido2-pin=on"
            );
            assert_eq!(
                BootConfig::parse("", &cmdline).key(&format!("luks-{root_uuid}")),
                BootKey::Secret
            );
            assert_eq!(
                BootConfig::parse(&crypttab, &cmdline).key("root"),
                BootKey::Hardware
            );
            let cmdline = format!(
                "{prefix}.name={root_uuid}=root {prefix}.options={swap_uuid}=tpm2-device=auto,tpm2-pin=yes"
            );
            assert_eq!(
                BootConfig::parse("", &cmdline).key("root"),
                BootKey::Unknown
            );
            let cmdline = format!(
                "{prefix}.name={root_uuid}=root {prefix}.options={root_uuid}=tpm2-device=auto,tpm2-pin=on"
            );
            assert_eq!(BootConfig::parse("", &cmdline).key("root"), BootKey::Secret);
        }
        let quoted = format!(
            "rd.luks.options=\"{root_uuid}=tpm2-device=auto,tpm2-pin=on,try-empty-password=TRUE\""
        );
        assert_eq!(
            BootConfig::parse(&crypttab, &quoted).key("root"),
            BootKey::Unknown
        );
        let bad = "root UUID=fictional - tpm2-device=auto,tpm2-pin=invalid";
        assert_eq!(BootConfig::parse(bad, "").key("root"), BootKey::Unknown);
        for cmdline in ["luks=off", "rd.luks=FALSE", "rd.luks.crypttab=no"] {
            assert_eq!(
                BootConfig::parse(&crypttab, cmdline).key("root"),
                BootKey::Unknown
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
