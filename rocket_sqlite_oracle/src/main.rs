use anyhow::Result;
use rocket::fairing::AdHoc;
use rocket::serde::json::Json;
use rocket::{get, routes, State};
use rocket_db_pools::{sqlx, Connection, Database};
use secp256k1::{PublicKey, SecretKey, Signature};
use secp256k1_zkp::SECP256K1;
use std::convert::TryInto;
use structopt::StructOpt;

mod cli;
mod db;

#[get("/")]
fn oracle_pubkey(key: &State<SecretKey>) -> String {
    PublicKey::from_secret_key(SECP256K1, key).to_string()
}

#[get("/ask/price")]
async fn current_ask_price(mut conn: Connection<db::Signatures>) -> Json<db::USDTickerResponse> {
    let row = sqlx::query!(
        r#"
        select
            timestamp,
            ask_price as price,
            units,
            ask_signature as signature
        from signatures
        order by timestamp desc
        limit 1;
        "#,
    )
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    let res = db::USDTickerResponse {
        timestamp: row.timestamp.try_into().unwrap(),
        price: row.price.try_into().unwrap(),
        units: row.units,
        signature: Signature::from_compact(&row.signature).unwrap(),
    };

    Json(res)
}

#[get("/bid/price")]
async fn current_bid_price(mut conn: Connection<db::Signatures>) -> Json<db::USDTickerResponse> {
    let row = sqlx::query!(
        r#"
        select
            timestamp,
            bid_price as price,
            units,
            bid_signature as signature
        from signatures
        order by timestamp desc
        limit 1;
        "#,
    )
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    let res = db::USDTickerResponse {
        timestamp: row.timestamp.try_into().unwrap(),
        price: row.price.try_into().unwrap(),
        units: row.units,
        signature: Signature::from_compact(&row.signature).unwrap(),
    };

    Json(res)
}

#[get("/ask/price/<timestamp>")]
async fn ask_price_at_time(
    mut conn: Connection<db::Signatures>,
    timestamp: i64,
) -> Json<db::USDTickerResponse> {
    let row = sqlx::query!(
        r#"
        with above as (
          select *
          from signatures
          where timestamp >= ?
          order by timestamp
          limit 1
        ),

        below as (
          select *
          from signatures
          where timestamp < ?
          order by timestamp desc
          limit 1
        ),

        opts as (
          select * from above
          union all
          select * from below
        )

        select
          timestamp,
          ask_price as price,
          units,
          ask_signature as signature
        from opts
        order by abs(? - timestamp)
        limit 1;
        "#,
        timestamp,
        timestamp,
        timestamp
    )
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    let res = db::USDTickerResponse {
        timestamp: row.timestamp.try_into().unwrap(),
        price: row.price.try_into().unwrap(),
        units: row.units,
        signature: Signature::from_compact(&row.signature).unwrap(),
    };

    Json(res)
}

#[get("/bid/price/<timestamp>")]
async fn bid_price_at_time(
    mut conn: Connection<db::Signatures>,
    timestamp: i64,
) -> Json<db::USDTickerResponse> {
    let row = sqlx::query!(
        r#"
        with above as (
          select *
          from signatures
          where timestamp >= ?
          order by timestamp
          limit 1
        ),

        below as (
          select *
          from signatures
          where timestamp < ?
          order by timestamp desc
          limit 1
        ),

        opts as (
          select * from above
          union all
          select * from below
        )

        select
          timestamp,
          bid_price as price,
          units,
          bid_signature as signature
        from opts
        order by abs(? - timestamp)
        limit 1;
        "#,
        timestamp,
        timestamp,
        timestamp
    )
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    let res = db::USDTickerResponse {
        timestamp: row.timestamp.try_into().unwrap(),
        price: row.price.try_into().unwrap(),
        units: row.units,
        signature: Signature::from_compact(&row.signature).unwrap(),
    };

    Json(res)
}

#[rocket::main]
async fn main() -> Result<(), anyhow::Error> {
    let xcli = cli::Cli::from_args();

    // TODO
    // this logic-flow isn't terribly user-friendly
    let oracle_secret = match xcli.generate_secret {
        true => {
            xcli.create_and_write_secret_key_to_file().await?;
            xcli.load_secret_key_from_file().await?
        }
        false => xcli.load_secret_key_from_file().await?,
    };

    rocket::build()
        .manage(oracle_secret)
        .attach(db::Signatures::init())
        .attach(AdHoc::try_on_ignite("SQL migrations", db::run_migrations))
        .attach(AdHoc::try_on_ignite("kraken ticker", db::write_signatures))
        .mount(
            "/",
            routes![
                current_ask_price,
                current_bid_price,
                ask_price_at_time,
                bid_price_at_time,
                oracle_pubkey
            ],
        )
        .launch()
        .await?;

    Ok(())
}
