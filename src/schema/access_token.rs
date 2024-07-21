// AccessToken schema as outlined in https://github.com/supabase/gotrue/blob/master/openapi.yaml

#[derive(serde::Deserialize, Debug, Clone)]
pub struct AccessToken {
    /// A valid JWT that will expire in `expires_in` seconds.
    pub access_token: String,

    /// An opaque string that can be used once to obtain a new access and refresh token.
    pub refresh_token: String,

    /// What type of token this is. Only `bearer` returned, may change in the future.
    pub token_type: String,

    /// Number of seconds after which the `access_token` should be renewed
    /// by using the refresh token with the `refresh_token` grant type
    pub expires_in: i32,

    /// UNIX timestamp after which the `access_token` should be renewed
    /// by using the refresh token with the `refresh_token` grant type
    pub expires_at: i64,

    /// Only returned on the `/token?grant_type=password` endpoint.
    /// When present, it indicates that the password used is weak.
    /// Inspect the `reasons` and/or `message` properties to identify why
    pub weak_password: Option<WeakPassword>,

    pub user: super::User,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct WeakPassword {
    pub reasons: Vec<String>,
    pub message: String,
}
