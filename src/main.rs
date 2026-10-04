use serde::Deserialize;
use warp::Filter;

mod handlers;

#[derive(Debug, Deserialize)]
struct Request {
    #[serde(rename = "apduHex")]
    apdu_hex: String,
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let address = args.next().unwrap_or_else(|| "127.0.0.1".into());
    let port = args
        .next()
        .and_then(|port| port.parse().ok())
        .unwrap_or(9999);
    let response_data = args.next().unwrap_or_else(|| "9000".into());
    if hex::decode(&response_data).is_err() {
        eprintln!("response data must be hexadecimal");
        std::process::exit(2);
    }

    let response_data = warp::any().map(move || response_data.clone());
    let route = warp::path::end()
        .and(warp::post())
        .and(warp::body::json())
        .and(response_data)
        .map(|request: Request, response_data: String| {
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
                warp::reply::json(&handlers::handle(&apdu, &response_data)),
                warp::http::StatusCode::OK,
            )
        });

    println!("ZEMU mock listening on http://{address}:{port}");
    let ip: std::net::IpAddr = address.parse().expect("bind address must be an IP address");
    warp::serve(route).run((ip, port)).await;
}
