use crate::errors::Error;
use crate::Supabase;

impl Supabase {
    /// Get a reference to the Prostgrest client.
    ///
    /// ```rust
    /// let supabase = Supabase::new(None, None, None);
    ///
    /// supabase.query().from("table").select("*").execute().await;
    ///
    /// supabase.query().rpc("function", r#"{"arg1": 1, "arg2": 2}"#)
    /// ```
    pub fn query(&self) -> &postgrest::Postgrest {
        &self.postgrest_client
    }
}

/// Parse the Postgrest response.
/// It requires a generic type that implements the `serde::Deserialize` trait.
pub async fn parse_response<T>(
    response: Result<reqwest::Response, reqwest::Error>,
) -> Result<Vec<T>, Error>
where
    T: serde::de::DeserializeOwned,
{
    Ok(
        crate::utils::parse_response(response, crate::utils::Parse::Postgrest)
            .await?
            .postgrest()
            .unwrap(),
    )
}
