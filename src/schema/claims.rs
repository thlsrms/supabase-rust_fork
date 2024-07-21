use serde::Deserialize;

use super::user::AppMetadata;

#[derive(Debug, Deserialize, Clone)]
pub struct Claims {
    pub aud: String,

    /// expiration time
    pub exp: i64,

    /// issued at
    pub iat: i64,

    /// issuer
    pub iss: String,

    /// subject
    pub sub: String,
    pub email: String,
    pub phone: String,
    pub app_metadata: AppMetadata,

    /// Type deserialized as `serde_json::Value`'s `Object` so it can be parsed based on the data stored.
    /// ```rust
    ///supabase_rust::parse_value::<MyUserMetadata>(...)
    /// ```
    pub user_metadata: serde_json::Value,
    pub role: String,
    pub aal: String,

    /// authentication methods array
    pub amr: Vec<AmrMethod>,
    pub session_id: String,
    pub is_anonymous: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AmrMethod {
    pub method: String,
    pub timestamp: i64,
}
