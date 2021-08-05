use anyhow::{Context, Result};
use secp256k1::rand::thread_rng;
use secp256k1::SecretKey;
use std::path::PathBuf;
use structopt::StructOpt;
use tokio::io::AsyncWriteExt;

#[derive(Debug, StructOpt)]
pub struct Cli {
    /// Path to the file that contains the secret key of the oracle secret key
    #[structopt(long)]
    pub secret: PathBuf,

    /// Set this flag to generate a secret file at the path specified by the
    /// --secret argument
    #[structopt(long)]
    pub generate_secret: bool,
}

impl Cli {
    pub async fn load_secret_key_from_file(&self) -> Result<SecretKey> {
        let path = &self.secret;
        let bytes = tokio::fs::read(path)
            .await
            .with_context(|| format!("No secret file at {}", path.display()))?;
        let secret_key = secp256k1::SecretKey::from_slice(&bytes)?;

        Ok(secret_key)
    }

    pub async fn create_and_write_secret_key_to_file(&self) -> Result<()> {
        let secret_key = SecretKey::new(&mut thread_rng());
        if let Some(parent) = self.secret.parent() {
            tokio::fs::DirBuilder::new()
                .recursive(true)
                .create(parent)
                .await
                .with_context(|| {
                    format!(
                        "Could not create directory for secret file: {}",
                        parent.display()
                    )
                })?;
        }
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.secret)
            .await
            .with_context(|| {
                format!(
                    "Could not generate secret file at {}",
                    self.secret.display()
                )
            })?;

        file.write_all(secret_key.as_ref()).await?;

        Ok(())
    }
}
