// Web handlers with an origin allowlist, secure cookies, local redirects and escaping.
use actix_cors::Cors;
use actix_web::cookie::{Cookie, SameSite};
use axum::extract::Query;
use axum::response::{Html, Redirect};
use std::io::Read;
use std::net::TcpStream;

const MAX_FRAME: usize = 1 << 20;

pub fn cors() -> Cors {
    Cors::default().allowed_origin("https://app.example.com").supports_credentials()
}

pub fn session_cookie(value: String) -> Cookie<'static> {
    Cookie::build("session", value).secure(true).http_only(true).same_site(SameSite::Lax).finish()
}

pub async fn login_done() -> Redirect {
    Redirect::to("/dashboard")
}

pub async fn greet(query: Query<Greeting>) -> Html<String> {
    Html(format!("<h1>Hello {}</h1>", html_escape::encode_text(&query.name)))
}

pub fn decode_message(body: &[u8]) -> Message {
    bincode::serde::decode_from_slice(body, bincode::config::standard().with_limit::<MAX_FRAME>()).unwrap().0
}

pub fn read_request(stream: TcpStream) -> Vec<u8> {
    let mut buffer = Vec::new();
    stream.take(MAX_FRAME as u64).read_to_end(&mut buffer).unwrap();
    buffer
}

pub fn read_frame(header: [u8; 4]) -> Vec<u8> {
    Vec::with_capacity((u32::from_be_bytes(header) as usize).min(MAX_FRAME))
}
