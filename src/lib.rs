use reqwest::Client;

pub(crate) mod auth;
mod client;
mod errors;
mod postgrest;
pub mod schema;
mod utils;

pub use errors::{AuthError, Error, ErrorKind, JwtErrorKind, PostgrestError};
pub use postgrest::parse_response;
pub use utils::parse_value;

#[derive(Clone)]
pub struct Supabase {
    client: Client,
    url: String,
    jwt: String,
    jwt_decoding_key: jsonwebtoken::DecodingKey,
    bearer_token: Option<String>,
    postgrest_client: ::postgrest::Postgrest,
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
