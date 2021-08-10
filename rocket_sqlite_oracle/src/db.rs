use anyhow::Context;
use baru::oracle::Message;
use rocket::serde::Serialize;
use rocket::{fairing, Build, Rocket, State};
use rocket_db_pools::{sqlx, Database};
use secp256k1::{SecretKey, Signature};
use std::convert::TryFrom;
use url::Url;

mod kraken;

#[derive(Database)]
#[database("signatures")]
pub struct Signatures(sqlx::SqlitePool);

#[derive(Serialize)]
pub struct USDTickerResponse {
    pub timestamp: u64,
    pub price: u64,
    pub units: String,
    pub signature: Signature,
}

pub async fn run_migrations(rocket: Rocket<Build>) -> fairing::Result {
    match Signatures::fetch(&rocket) {
        Some(db) => match sqlx::migrate!("./migrations").run(&**db).await {
            Ok(_) => Ok(rocket),
            Err(_) => Err(rocket),
        },
        None => Err(rocket),
    }
}

pub async fn write_signatures(rocket: Rocket<Build>) -> fairing::Result {
    let db = match Signatures::fetch(&rocket) {
        Some(db) => (**db).clone(),
        None => return Err(rocket),
    };

    let key = State::<SecretKey>::get(&rocket).unwrap();
    let key = **key;

    tokio::spawn(async move {
        let price_ticker_ws_url = Url::parse("wss://ws.kraken.com").unwrap();
        let mut ticker = kraken::connect(price_ticker_ws_url)
            .context("Failed to connect to kraken")
            .unwrap();

        loop {
            match ticker.wait_for_next_update().await.unwrap() {
                Ok(update) => {
                    let ask_signature = Message::new(update.ask.exchange_rate, update.timestamp)
                        .sign(&key)
                        .serialize_compact()
                        .to_vec();
                    let bid_signature = Message::new(update.bid.exchange_rate, update.timestamp)
                        .sign(&key)
                        .serialize_compact()
                        .to_vec();
                    let timestamp = i64::try_from(update.timestamp).unwrap();
                    let ask = i64::try_from(update.ask.exchange_rate).unwrap();
                    let bid = i64::try_from(update.bid.exchange_rate).unwrap();
                    sqlx::query!(
                        r"
                        insert into signatures (
                          timestamp,
                          ask_price,
                          bid_price,
                          ask_signature,
                          bid_signature
                        ) values (?, ?, ?, ?, ?)",
                        timestamp,
                        ask,
                        bid,
                        ask_signature,
                        bid_signature,
                    )
                    .execute(&db)
                    .await
                    .unwrap();
                }
                Err(e) => println!("Error: {:#}", e),
            }
        }
    });

    Ok(rocket)
}
