use super::*;
use std::io::{Read, Write};

#[derive(Subcommand)]
pub enum Command {
    /// Read TOML from stdin and make it active
    Set {
        #[arg(long, default_value = "")]
        note: String,
        #[arg(long)]
        json: bool,
    },
    /// List stored versions, newest first
    History {
        #[arg(long)]
        json: bool,
    },
    /// Print stored TOML, active by default
    Get {
        #[arg(long)]
        version: Option<i64>,
    },
    /// Restore a stored version
    Activate {
        version: i64,
        #[arg(long)]
        json: bool,
    },
}

#[derive(sqlx::FromRow, serde::Serialize)]
pub struct Version {
    pub version: i64,
    #[serde(skip)]
    pub toml: String,
    #[serde(rename = "manifest_hash")]
    pub hash: String,
    created_at: chrono::DateTime<chrono::Utc>,
    note: String,
    active: bool,
}

pub async fn active(db: &PgPool) -> anyhow::Result<Option<Version>> {
    Ok(
        sqlx::query_as("SELECT * FROM manifest_versions WHERE active")
            .fetch_optional(db)
            .await?,
    )
}

pub fn enforced(toml: &str, keys: &Keys, version: Option<i64>) -> anyhow::Result<Enforced> {
    let manifest = Manifest::parse(toml.as_bytes())?;
    let log = Log {
        key: log_key(keys)?,
        signer: keys.log.clone(),
        witnesses: Witnesses::new(witness_urls(), manifest.body().log.as_ref())?,
        cache: Mutex::default(),
    };
    Ok(Enforced {
        siem: None,
        company: Endorsement::sign(&keys.manifest, manifest.hash()),
        manifest: Arc::new(manifest),
        toml: toml.into(),
        log: Arc::new(log),
        version,
    })
}

async fn change(
    db: &PgPool,
    keys: &Keys,
    text: Option<(&str, &str)>,
    version: Option<i64>,
) -> anyhow::Result<Value> {
    let mut tx = db.begin().await?;
    sqlx::query("LOCK TABLE manifest_versions IN EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await?;
    let previous: Option<String> =
        sqlx::query_scalar("SELECT hash FROM manifest_versions WHERE active")
            .fetch_optional(&mut *tx)
            .await?;
    let previous = match previous {
        Some(hash) => hash,
        None => read_manifest()?.2.hash().to_string(),
    };
    let (toml, note) = match text {
        Some((toml, note)) => (toml.to_owned(), note.to_owned()),
        None => {
            let toml: String =
                sqlx::query_scalar("SELECT toml FROM manifest_versions WHERE version = $1")
                    .bind(version)
                    .fetch_optional(&mut *tx)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("manifest version does not exist"))?;
            (toml, String::new())
        }
    };
    let enforced = enforced(&toml, keys, version)?;
    witness_refresh(&enforced.manifest, &enforced.log.witnesses)?;
    let hash = enforced.manifest.hash().to_string();
    sqlx::query("UPDATE manifest_versions SET active = false WHERE active")
        .execute(&mut *tx)
        .await?;
    let version = match version {
        Some(version) => {
            sqlx::query("UPDATE manifest_versions SET active = true WHERE version = $1")
                .bind(version).execute(&mut *tx).await?;
            version
        }
        None => sqlx::query_scalar::<_, i64>("INSERT INTO manifest_versions(toml, hash, note, active) VALUES ($1, $2, $3, true) RETURNING version")
            .bind(toml).bind(&hash).bind(note).fetch_one(&mut *tx).await?,
    };
    publish_manifest_in(&mut tx, &enforced.manifest).await?;
    tx.commit().await?;
    Ok(json!({"version": version, "manifest_hash": hash, "previous_hash": previous}))
}

pub async fn run(db: &PgPool, command: Command) -> anyhow::Result<()> {
    match command {
        Command::History { .. } => {
            let rows: Vec<Version> =
                sqlx::query_as("SELECT * FROM manifest_versions ORDER BY version DESC")
                    .fetch_all(db)
                    .await?;
            println!("{}", serde_json::to_string(&rows)?);
        }
        Command::Get { version } => {
            let toml: String = match version {
                Some(version) => {
                    sqlx::query_scalar("SELECT toml FROM manifest_versions WHERE version = $1")
                        .bind(version)
                        .fetch_optional(db)
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("manifest version does not exist"))?
                }
                None => match active(db).await? {
                    Some(row) => row.toml,
                    None => read_manifest()?.1,
                },
            };
            std::io::stdout().write_all(toml.as_bytes())?;
        }
        command => {
            let mut toml = String::new();
            if matches!(command, Command::Set { .. }) {
                std::io::stdin().read_to_string(&mut toml)?;
            }
            let keys = Keys::load_or_create(db, &SealingKey::kek_from_env()?).await?;
            let document = match command {
                Command::Set { note, .. } => change(db, &keys, Some((&toml, &note)), None).await?,
                Command::Activate { version, .. } => change(db, &keys, None, Some(version)).await?,
                _ => unreachable!(),
            };
            println!("{document}");
        }
    }
    Ok(())
}

#[cfg(test)]
pub async fn set_for_test(db: &PgPool, keys: &Keys, toml: &str) {
    change(db, keys, Some((toml, "test")), None).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
    async fn versions_preserve_text_restore_and_reject_invalid_input() {
        let db = testdb::fresh().await;
        let keys = Keys::load_or_create(&db, &SealingKey::new(&[5; 32]))
            .await
            .unwrap();
        let a = include_str!("../../../examples/manifest.toml");
        let b = format!("{a}\n# FICTIONAL revision\n");
        let first = change(&db, &keys, Some((a, "first")), None).await.unwrap();
        let second = change(&db, &keys, Some((&b, "second")), None)
            .await
            .unwrap();
        assert_eq!(second["previous_hash"], first["manifest_hash"]);
        let row = active(&db).await.unwrap().unwrap();
        assert_eq!(row.toml, b);
        assert_eq!(row.version, second["version"].as_i64().unwrap());
        assert!(
            change(&db, &keys, Some(("invalid", "bad")), None)
                .await
                .is_err()
        );
        assert!(change(&db, &keys, None, Some(999)).await.is_err());
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM manifest_versions")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(active(&db).await.unwrap().unwrap().version, row.version);
        let restored = change(&db, &keys, None, first["version"].as_i64())
            .await
            .unwrap();
        assert_eq!(restored["previous_hash"], second["manifest_hash"]);
        assert_eq!(active(&db).await.unwrap().unwrap().toml, a);
        let (left, right) = tokio::join!(
            change(&db, &keys, Some((a, "concurrent A")), None),
            change(&db, &keys, Some((&b, "concurrent B")), None),
        );
        assert!(left.is_ok() && right.is_ok());
        let active_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM manifest_versions WHERE active")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(active_count, 1);
    }
}
