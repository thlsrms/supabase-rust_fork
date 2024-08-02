use serde::{Deserialize, Serialize};

use crate::auth::helper::auth_error;
use crate::errors::Error;
use crate::schema::{AccessToken, MFAFactor};
use crate::Supabase;

use super::parse_auth_response;

#[derive(Serialize, Deserialize)]
pub struct MFAEnroll {
    pub id: String,
    #[serde(rename = "type")]
    pub factor_type: FactorType,
    pub totp: MFATotp,
    pub friendly_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct MFATotp {
    pub qr_code: String,
    pub secret: String,
    pub uri: String,
}

#[derive(Serialize, Deserialize)]
pub struct MFAChallenge {
    pub id: String,
    pub expires_at: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum FactorType {
    #[serde(alias = "totp", alias = "TOTP")]
    TOTP,
}

impl std::fmt::Display for FactorType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::TOTP => write!(f, "totp"),
        }
    }
}

impl Supabase {
    /// Starts the enrollment process for a new Multi-Factor Authentication (MFA) factor.
    /// This function creates a new unverified factor.
    ///
    /// To verify a factor, present the QR code or secret to the user and ask them to
    /// add it to their authenticator app.
    ///
    /// Currently, time-based one-time password (TOTP) is the only supported factor type.
    /// The returned id should be used to create a challenge.
    pub async fn mfa_enroll(
        &self,
        friendly_name: Option<String>,
        user_token: &str,
        factor_type: FactorType,
    ) -> Result<MFAEnroll, Error> {
        let request_url: String = format!("{0}/auth/v1/factors", self.url);
        let response = self
            .client
            .post(&request_url)
            .json(&EnrollRequest {
                factor_type: factor_type.to_string(), // Only supported type
                friendly_name,
                issuer: Some(format!("{0}/auth/v1", self.url)),
            })
            .bearer_auth(user_token)
            .send()
            .await;
        parse_auth_response::<MFAEnroll>(response).await
    }

    /// Prepares a challenge used to verify that a user has access to a MFA factor
    pub async fn mfa_challenge(
        &self,
        factor_id: String,
        user_token: &str,
    ) -> Result<MFAChallenge, Error> {
        let url: String = format!("{0}/auth/v1/factors/{factor_id}/challenge", self.url);
        let response = self.client.post(&url).bearer_auth(user_token).send().await;
        parse_auth_response::<MFAChallenge>(response).await
    }

    /// Verifies a code against a challenge. The verification is provided by the user entering
    /// a code seen in their authenticator app.
    pub async fn mfa_verify(
        &self,
        factor_id: String,
        challenge_id: String,
        code: String,
        user_token: &str,
    ) -> Result<AccessToken, Error> {
        let url: String = format!("{0}/auth/v1/factors/{factor_id}/verify", self.url);
        let response = self
            .client
            .post(&url)
            .json(&VerifyRequest { challenge_id, code })
            .bearer_auth(user_token)
            .send()
            .await;
        parse_auth_response::<AccessToken>(response).await
    }

    /// Creates a challenge and immediately uses the given code to verify against it thereafter.
    /// The verification code is provided by the user entering a code seen in their authenticator app.
    pub async fn mfa_challenge_and_verify(
        &self,
        factor_id: String,
        code: String,
        user_token: &str,
    ) -> Result<AccessToken, Error> {
        let challenge = self.mfa_challenge(factor_id.clone(), user_token).await?;
        self.mfa_verify(factor_id, challenge.id, code, user_token)
            .await
    }

    /// List all of the MFA factors for a user
    pub async fn mfa_list_factors(
        &self,
        user_id: String,
        admin_token: &str,
    ) -> Result<Vec<MFAFactor>, Error> {
        let url: String = format!("{0}/auth/v1/admin/users/{user_id}/factors", self.url);
        let response = self.client.get(&url).bearer_auth(admin_token).send().await;
        parse_auth_response::<Vec<MFAFactor>>(response).await
    }

    /// Remove a MFA factor from a user. Return its ID if successful
    /// The MFA factor will be removed (unenrolled) and cannot be used for increasing the
    /// Authenticator Assurance Level of the user's sessions.
    /// After removal the `refresh_token` endpoint should be used to get a new access and refresh
    /// token with decreased AAL.
    pub async fn mfa_delete_factor(
        &self,
        factor_id: String,
        user_token: &str,
    ) -> Result<String, Error> {
        let url: String = format!("{0}/auth/v1/factors/{factor_id}", self.url);
        let response = self
            .client
            .delete(&url)
            .bearer_auth(user_token)
            .send()
            .await;

        parse_auth_response::<MFADeleted>(response)
            .await
            .map(|f| f.id)
    }

    /// Update a user's MFA factor
    pub async fn mfa_update_factor(
        &self,
        factor_id: String,
        user_id: String,
        friendly_name: String,
        admin_token: &str,
    ) -> Result<MFAFactor, Error> {
        let url = format!(
            "{0}/auth/v1/admin/users/{user_id}/factors/{factor_id}",
            self.url
        );
        let updated_name = serde_json::from_str::<serde_json::Value>(&format!(
            r#"{{"friendly_name": "{}"}}"#,
            friendly_name
        ))
        .map_err(|e| {
            auth_error(
                500,
                &format!("Error serializing 'mfa_update_factor' request: {e}"),
            )
        })?;

        let response = self
            .client
            .put(&url)
            .json(&updated_name)
            .bearer_auth(admin_token)
            .send()
            .await;
        parse_auth_response::<MFAFactor>(response).await
    }
}

#[derive(Deserialize)]
struct MFADeleted {
    id: String,
}

#[derive(Serialize)]
struct EnrollRequest {
    factor_type: String,
    friendly_name: Option<String>,
    issuer: Option<String>,
}

#[derive(Serialize)]
struct VerifyRequest {
    challenge_id: String,
    code: String,
}
