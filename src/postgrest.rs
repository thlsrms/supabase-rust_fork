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
