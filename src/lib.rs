use reqwest::Client;

pub mod auth;
mod client;
mod db;
mod errors;
mod schema;
mod utils;

#[derive(Clone)]
pub struct Supabase {
    client: Client,
    url: String,
    jwt: String,
    bearer_token: Option<String>,
    db: postgrest::Postgrest,
}

impl std::fmt::Debug for Supabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Supabase")
            .field("client", &self.client)
            .field("url", &self.url)
            .field("jwt", &self.jwt)
            .field("bearer_token", &self.bearer_token)
            .finish_non_exhaustive()
    }
}
