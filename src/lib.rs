use reqwest::Client;

mod auth;
mod client;
mod db;

pub struct Supabase {
    client: Client,
    url: String,
    jwt: String,
    bearer_token: Option<String>,
    db: postgrest::Postgrest,
}
