use serde::{Deserialize, Serialize};

/// Schema describing the user related to the issued access and refresh tokens
/// as outlined in https://github.com/supabase/gotrue/blob/master/openapi.yaml
///
#[derive(Deserialize, Debug, Clone)]
pub struct User {
    /// format: uuid
    pub id: String,

    /// deprecated
    pub aud: String,

    pub role: String,

    /// User's primary contact email.
    /// In most cases you can uniquely identify a user by their email address, but not in all cases.
    pub email: String,

    /// format: date-time
    pub email_confirmed_at: String,

    /// format: phone
    /// User's primary contact phone number.
    /// In most cases you can uniquely identify a user by their email address, but not in all cases.
    pub phone: String,

    /// format: date-time
    pub phone_confirmed_at: Option<String>,

    /// format: date-time
    pub confirmation_sent_at: Option<String>,

    /// format: date-time
    pub confirmed_at: Option<String>,

    /// format: date-time
    pub recovery_sent_at: Option<String>,

    /// format: email
    pub new_email: Option<String>,

    /// format: date-time
    pub email_change_sent_at: Option<String>,

    /// format: phone
    pub new_phone: Option<String>,

    /// format: date-time
    pub phone_change_sent_at: Option<String>,

    /// format: date-time
    pub reauthentication_sent_at: Option<String>,

    /// format: date-time
    pub last_sign_in_at: String,

    pub app_metadata: AppMetadata,

    /// User metadata is stored on the `raw_user_meta_data` column of the `auth.users` table.
    /// Type deserialized as `serde_json::Value`'s `Object` so it can be parsed based on the data stored.
    /// ```rust
    ///supabase_rust::parse_value::<MyUserMetadata>(...)
    /// ```
    pub user_metadata: serde_json::Value,

    pub factors: Option<Vec<MFAFactor>>,

    pub identities: Vec<Identity>,

    /// format: date-time
    pub banned_until: Option<String>,

    /// format: date-time
    pub created_at: String,

    /// format: date-time
    pub updated_at: String,

    /// format: date-time
    pub deleted_at: Option<String>,

    pub is_anonymous: bool,
}

/// Represents a MFA factor.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MFAFactor {
    /// format: uuid
    pub id: String,

    /// Usually one of:
    ///     - verified
    ///     - unverified
    pub status: MFAFactorStatus,

    pub friendly_name: Option<String>,

    /// Usually one of:
    ///     - totp
    pub factor_type: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MFAFactorStatus {
    #[serde(alias = "verified")]
    Verified,
    #[serde(alias = "unverified")]
    Unverified,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AppMetadata {
    pub provider: String,
    pub providers: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Identity {
    /// format: uuid
    pub id: String,

    /// format: uuid
    pub user_id: String,

    /// Type deserialized as `serde_json::Value`'s `Object` so it can be parsed based on the data stored.
    /// ```rust
    ///supabase_rust::parse_value::<MyOAuthProviderScopedData>(...)
    /// ```
    pub identity_data: serde_json::Value,

    pub provider: String,

    /// format: date-time
    pub last_sign_in_at: String,

    /// format: date-time
    pub created_at: String,

    /// format: date-time
    pub updated_at: String,

    /// format: email
    pub email: String,
}
