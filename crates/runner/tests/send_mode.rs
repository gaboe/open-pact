use runner::manifest::{self, Form};

const VPN: &str = "manifest_version = 1

[schedule]
mode = \"vpn\"
vpn_probe = \"10.0.0.2:443\"
vpn_probe_name = \"Office VPN\"
interval = \"1h\"
";

#[test]
fn the_vpn_probe_and_name_come_back_when_the_vpn_is_chosen_again() {
    let mut kept = None;
    let always = manifest::switch_send_mode(VPN, "always", &mut kept).unwrap();
    let schedule = Form::parse(&always).unwrap().schedule.unwrap();
    assert_eq!(schedule.mode, "always");
    assert!(!always.contains("vpn_probe"));
    let back = manifest::switch_send_mode(&always, "vpn", &mut kept).unwrap();
    let schedule = Form::parse(&back).unwrap().schedule.unwrap();
    assert_eq!(schedule.mode, "vpn");
    assert_eq!(schedule.probe, "10.0.0.2:443");
    assert_eq!(schedule.name, "Office VPN");
}
