//! The standing of a device, as `claims list` and `claims show` print it. The command derives it
//! when it runs, from the device's last claim decision and the clock. No job writes it, and the
//! gateway revokes no certificate.

use chrono::{DateTime, TimeDelta, Utc};
use open_pact_core::{Manifest, Place};
use serde::Serialize;
use sqlx::PgPool;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Standing {
    /// The last claim was accepted, and its certificate has not ended.
    Current,
    /// The certificate ended, and no newer claim renewed it.
    Lapsed,
    /// The last claim was accepted before the gateway kept the end of its certificate, so the
    /// gateway cannot tell whether it still runs. The next claim ends the doubt.
    Unknown,
    /// The last claim was denied.
    Denied,
    /// No claim within twice the send interval, or no claim at all.
    Silent,
}

/// The last claim decision of a device: the newest one over its enrolments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastDecision {
    pub at: DateTime<Utc>,
    pub denied: bool,
    /// The end of the certificate that claim got. None for a denial and for a claim without one.
    pub access_until: Option<DateTime<Utc>>,
    /// The manifest the claim was made under.
    pub manifest: String,
}

/// The send interval on the VPN, which is the one `vpn_lease` doubles. None without a schedule.
pub fn send_interval(manifest: Option<&Manifest>) -> Option<TimeDelta> {
    let interval = manifest?.body().schedule.as_ref()?.period(Place::Vpn)?;
    TimeDelta::try_seconds(interval.as_secs())
}

/// The standing at `now`. A denial stands until a newer claim. A certificate that has not ended
/// keeps the device current, and an accepted claim with no recorded end leaves it unknown.
/// Otherwise the device is silent when its last claim is older than twice the send interval, and
/// lapsed when it is not. Without a schedule, no silence is judged.
pub fn standing(
    last: Option<&LastDecision>,
    send_interval: Option<TimeDelta>,
    now: DateTime<Utc>,
) -> Standing {
    let Some(last) = last else {
        return Standing::Silent;
    };
    if last.denied {
        return Standing::Denied;
    }
    let Some(until) = last.access_until else {
        return Standing::Unknown;
    };
    if now < until {
        return Standing::Current;
    }
    match send_interval {
        Some(every) if now - last.at > every * 2 => Standing::Silent,
        _ => Standing::Lapsed,
    }
}

/// The newest decision of the device over its enrolments, or None when it never claimed.
pub async fn last_decision(db: &PgPool, device: &str) -> anyhow::Result<Option<LastDecision>> {
    type Row = (DateTime<Utc>, String, Option<DateTime<Utc>>, String);
    let row: Option<Row> = sqlx::query_as(
        "SELECT last_claim_at, last_result, last_access_until, manifest_hash FROM devices \
         WHERE pseudonym = $1 AND last_claim_at IS NOT NULL ORDER BY last_claim_at DESC LIMIT 1",
    )
    .bind(device)
    .fetch_optional(db)
    .await?;
    Ok(
        row.map(|(at, result, access_until, manifest)| LastDecision {
            at,
            denied: result == "denied",
            access_until,
            manifest,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> DateTime<Utc> {
        text.parse().unwrap()
    }

    fn decision(denied: bool, access_until: Option<&str>) -> LastDecision {
        LastDecision {
            at: at("2026-11-17T09:00:00Z"),
            denied,
            access_until: access_until.map(at),
            manifest: "m".into(),
        }
    }

    #[test]
    fn a_device_without_a_decision_is_silent() {
        let now = at("2026-11-17T09:05:00Z");
        assert_eq!(standing(None, None, now), Standing::Silent);
    }

    #[test]
    fn a_denial_stands_even_while_an_older_certificate_would_run() {
        let now = at("2026-11-17T09:05:00Z");
        let last = decision(true, Some("2026-11-17T11:00:00Z"));
        assert_eq!(standing(Some(&last), None, now), Standing::Denied);
    }

    #[test]
    fn a_certificate_that_has_not_ended_is_current() {
        let last = decision(false, Some("2026-11-17T10:00:00Z"));
        let before = at("2026-11-17T09:59:59Z");
        assert_eq!(
            standing(Some(&last), Some(TimeDelta::minutes(55)), before),
            Standing::Current
        );
    }

    #[test]
    fn an_ended_certificate_with_a_recent_claim_is_lapsed() {
        let last = decision(false, Some("2026-11-17T09:30:00Z"));
        let now = at("2026-11-17T10:00:00Z");
        assert_eq!(
            standing(Some(&last), Some(TimeDelta::minutes(55)), now),
            Standing::Lapsed
        );
    }

    #[test]
    fn no_claim_within_twice_the_send_interval_is_silent() {
        let last = decision(false, Some("2026-11-17T09:30:00Z"));
        let at_the_limit = at("2026-11-17T10:50:00Z");
        assert_eq!(
            standing(Some(&last), Some(TimeDelta::minutes(55)), at_the_limit),
            Standing::Lapsed,
            "exactly twice the interval is still in time"
        );
        let past = at("2026-11-17T10:50:01Z");
        assert_eq!(
            standing(Some(&last), Some(TimeDelta::minutes(55)), past),
            Standing::Silent
        );
    }

    #[test]
    fn without_a_schedule_no_silence_is_judged() {
        let last = decision(false, Some("2026-11-17T09:00:00Z"));
        let long_after = at("2027-01-01T00:00:00Z");
        assert_eq!(standing(Some(&last), None, long_after), Standing::Lapsed);
    }

    /// A row from before the gateway kept the certificate end holds no end. Its certificate may
    /// still run, so the standing is unknown at any time, never lapsed or silent.
    #[test]
    fn an_accepted_claim_with_no_recorded_end_is_unknown() {
        let last = decision(false, None);
        for now in ["2026-11-17T09:05:00Z", "2026-11-18T09:05:00Z"] {
            for interval in [None, Some(TimeDelta::minutes(55))] {
                assert_eq!(
                    standing(Some(&last), interval, at(now)),
                    Standing::Unknown,
                    "{now} {interval:?}"
                );
            }
        }
        let denied = decision(true, None);
        assert_eq!(
            standing(Some(&denied), None, at("2026-11-17T09:05:00Z")),
            Standing::Denied
        );
    }

    #[test]
    fn the_send_interval_is_the_vpn_period_of_the_manifest() {
        let demo = Manifest::parse(include_bytes!("../../../examples/manifest.toml")).unwrap();
        assert_eq!(send_interval(Some(&demo)), Some(TimeDelta::minutes(55)));
        assert_eq!(send_interval(None), None);
    }
}
