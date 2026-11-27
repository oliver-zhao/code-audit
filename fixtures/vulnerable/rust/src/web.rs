// Web handlers: CORS, cookies, redirects, HTML and request sizes.
use actix_cors::Cors;
use actix_web::cookie::{Cookie, SameSite};
use axum::extract::Query;
use axum::response::{Html, Redirect};
use std::io::Read;
use std::net::TcpStream;

pub fn cors() -> Cors {
    Cors::permissive()
}

pub fn cors_any_origin() -> Cors {
    Cors::default().allow_any_origin().supports_credentials()
}

pub fn session_cookie(value: String) -> Cookie<'static> {
    Cookie::build("session", value).secure(false).http_only(false).same_site(SameSite::None).finish()
}

pub async fn login_done(query: Query<Next>) -> Redirect {
    Redirect::to(&query.next)
}

pub async fn greet(query: Query<Greeting>) -> Html<String> {
    Html(format!("<h1>Hello {}</h1>", query.name))
}

pub fn decode_message(body: &[u8]) -> Message {
    bincode::deserialize(body).unwrap()
}

pub fn read_request(mut stream: TcpStream) -> Vec<u8> {
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).unwrap();
    buffer
}

pub fn read_frame(header: [u8; 4]) -> Vec<u8> {
    Vec::with_capacity(u32::from_be_bytes(header) as usize)
}
