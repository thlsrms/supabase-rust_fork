use postgrest::Postgrest;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    ClientBuilder,
};
use std::env;

use crate::Supabase;

impl Supabase {
    // Creates a new Supabase client. If no parameters are provided, it will attempt to read the
    // environment variables `SUPABASE_URL`, `SUPABASE_API_KEY`, and `SUPABASE_JWT_SECRET`.
    pub fn new(url: Option<&str>, api_key: Option<&str>, jwt: Option<&str>) -> Self {
        let url: String = url
            .map(String::from)
            .unwrap_or_else(|| env::var("SUPABASE_URL").unwrap_or_else(|_| String::new()));
        let api_key: String = api_key
            .map(String::from)
            .unwrap_or_else(|| env::var("SUPABASE_API_KEY").unwrap_or_else(|_| String::new()));
        let jwt: String = jwt
            .map(String::from)
            .unwrap_or_else(|| env::var("SUPABASE_JWT_SECRET").unwrap_or_else(|_| String::new()));
        let postgrest: Postgrest =
            Postgrest::new(format!("{}/rest/v1", url.to_owned())).insert_header("apikey", &api_key);

        let mut default_headers = HeaderMap::new();
        default_headers.insert("apikey", HeaderValue::from_str(&api_key).unwrap());
        default_headers.insert("Content-Type", HeaderValue::from_static("application/json"));

        let client = ClientBuilder::new()
            .default_headers(default_headers)
            .build()
            .unwrap();

        Supabase {
            client,
            url: url.to_string(),
            jwt: jwt.to_string(),
            bearer_token: None,
            postgrest_client: postgrest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client() {
        let client: Supabase = Supabase::new(None, None, None);
        let url = client.url.clone();
        assert!(client.url == url);
    }
}
