use serde::Serialize;

use crate::errors::Error;
use crate::schema::AccessToken;
use crate::Supabase;

use super::parse_auth_response;

#[derive(Default)]
pub struct OAuthOptions {
    /// List of OAuth scopes to pass on to `provider`.
    pub scopes: Vec<String>,
    /// A token representing a previous invitation of the user.
    /// A successful sign-in with OAuth will mark the invitation as completed.
    pub invite_token: Option<String>,
    /// URL to redirect back into the app after OAuth sign-in completes successfully or not.
    /// If not specified will use the "Site URL" configuration option.
    /// If not allowed per the allow list it will use the "Site URL" configuration option.
    pub redirect_to: Option<String>,
    /// The Proof Key for Code Exchange (PKCE) flow is one of two ways that a user can authenticate
    /// and your app can receive the necessary access and refresh tokens.
    /// Implicit flow will be used if not provided.
    pub pkce: Option<PKCECodeChallenge>,
}

/// The method to encrypt the PKCE code verifier value can be:
///
/// Plain (no transformation):
///     - code_challenge = code_verifier
/// S256 (where SHA-256 is used):
///     - code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
///
/// code_verifier = high-entropy cryptographic random STRING using the unreserved characters
/// that are allowed in a URI `[A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"`
/// with a minimum length of 43 characters and a maximum length of 128 characters.
///
/// The `exchange_code_for_session` function can be used to verify the `auth_code` received
/// from the OAuth provider and exchange for an `AccessToken`.
///
/// It is always recommended that `S256` be used.
#[derive(Debug)]
pub enum PKCECodeChallenge {
    S256(String),
    Plain(String),
}

impl PKCECodeChallenge {
    pub fn value(&self) -> &str {
        match self {
            PKCECodeChallenge::S256(v) | PKCECodeChallenge::Plain(v) => v,
        }
    }
}

#[derive(Serialize)]
struct PKCEGrantParams {
    auth_code: String,
    code_verifier: String,
}

impl Supabase {
    /// Get the Redirect URL to authenticate through an external oauth provider.
    /// Redirects to the provider and then to `/callback` which will redirect to your app.
    ///
    /// If Proof Key for Code Exchange (PKCE) flow is not being used, implicit flow is then used.
    /// After a successful sign in using implicit flow, the user is redirected to your app with a
    /// URL containing the following parameters in its fragment identifier:
    /// REDIRECT_URL#
    ///     - access_token=...&
    ///     - expires_at=...&
    ///     - expires_in=...&
    ///     - provider_refresh_token=...&
    ///     - provider_token=...&
    ///     - refresh_token=...&
    ///     - token_type=bearer
    ///
    /// When using PKCE flow the redirect URL contains a single parameter: REDIRECT_URL?code=...
    /// which can be verified and exchanged for an `AccessToken` with the `exchange_code_for_session` function.
    pub async fn sign_in_oauth(&self, provider: &str, options: OAuthOptions) -> String {
        let scopes = options.scopes.join(" ");
        let mut request_url: String = format!(
            "{0}/auth/v1/authorize?provider={provider}&scopes={scopes}",
            self.url
        );

        if let Some(invite_token) = options.invite_token {
            request_url.push_str(&format!("&invite_token={invite_token}"));
        }

        if let Some(code_challenge) = options.pkce {
            match code_challenge {
                PKCECodeChallenge::S256(code) => {
                    request_url.push_str(&format!(
                        "&code_challenge_method=s256&code_challenge={code}",
                    ));
                }
                PKCECodeChallenge::Plain(code) => {
                    request_url.push_str(&format!(
                        "&code_challenge_method=plain&code_challenge={code}",
                    ));
                }
            }
        }

        if let Some(redirect_to) = options.redirect_to {
            request_url.push_str(&format!("&redirect_to={redirect_to}"));
        }

        request_url
    }

    /// Log in an existing user by exchanging an Auth Code issued during the PKCE flow.
    pub async fn exchange_code_for_session(
        &self,
        auth_code: &str,
        code_verifier: &str,
    ) -> Result<AccessToken, Error> {
        let request_url: String = format!("{}/auth/v1/token?grant_type=pkce", self.url);
        let response = self
            .client
            .post(&request_url)
            .json(&PKCEGrantParams {
                auth_code: auth_code.into(),
                code_verifier: code_verifier.into(),
            })
            .send()
            .await;
        parse_auth_response::<AccessToken>(response).await
    }
}
