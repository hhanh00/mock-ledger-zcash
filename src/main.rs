use clap::{Parser, ValueEnum};
use serde::Deserialize;
use warp::Filter;

mod handlers;

#[derive(Debug, Deserialize)]
struct Request {
    #[serde(rename = "apduHex")]
    apdu_hex: String,
}

#[derive(Debug, Parser)]
#[command(
    name = "mock-ledger-zcash",
    about = "Mock Ledger Zcash app HTTP transport"
)]
struct Args {
    /// Chain network used by the mock Ledger app.
    #[arg(long, value_enum, default_value_t = Network::Mainnet)]
    network: Network,
    /// Network upgrade to expose to mock handlers.
    #[arg(long)]
    network_upgrade: Option<String>,
    /// Optional device seed phrase used by mock handlers.
    #[arg(long)]
    seed_phrase: Option<String>,
    /// Account index used by the mock Ledger app.
    #[arg(long, default_value_t = 0)]
    account_index: u32,
    /// Address to bind to.
    #[arg(long, default_value = "127.0.0.1")]
    address: String,
    /// TCP port to listen on.
    #[arg(short, long, default_value_t = 9999)]
    port: u16,
    /// Hexadecimal APDU response returned by every mock handler.
    #[arg(long, default_value = "9000")]
    response_data: String,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    // These values define the mock app context. Handlers intentionally do not
    // use them yet; no Ledger business logic is implemented.
    let seed_phrase = args.seed_phrase.clone();
    let account_index = args.account_index;
    let network = args.network;
    let _ = &args.network_upgrade;
    let address = args.address;
    let port = args.port;
    let response_data = args.response_data;
    if hex::decode(&response_data).is_err() {
        eprintln!("response data must be hexadecimal");
        std::process::exit(2);
    }

    let response_data = warp::any().map(move || response_data.clone());
    let route = warp::path::end()
        .and(warp::post())
        .and(warp::body::json())
        .and(response_data)
        .map(move |request: Request, response_data: String| {
            let Ok(bytes) = hex::decode(request.apdu_hex) else {
                return warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "error": "expected hexadecimal apduHex"
                    })),
                    warp::http::StatusCode::BAD_REQUEST,
                );
            };
            let Ok(apdu) = handlers::parse_apdu(&bytes) else {
                return warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "error": "invalid APDU header or length"
                    })),
                    warp::http::StatusCode::BAD_REQUEST,
                );
            };
            warp::reply::with_status(
                warp::reply::json(&handlers::handle(
                    &apdu,
                    &response_data,
                    seed_phrase.as_deref(),
                    account_index,
                    network,
                )),
                warp::http::StatusCode::OK,
            )
        });

    println!("ZEMU mock listening on http://{address}:{port}");
    let ip: std::net::IpAddr = address.parse().expect("bind address must be an IP address");
    warp::serve(route).run((ip, port)).await;
}
