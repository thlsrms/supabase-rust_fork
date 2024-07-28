use jsonwebtoken::{decode, Algorithm, Validation};
use reqwest::Response;
use serde::{Deserialize, Serialize};

use crate::errors::{AuthError, Error, ErrorKind};
use crate::schema::{AccessToken, Claims, User};
use crate::Supabase;

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
/// It has to be between 43 and 128 characters.
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
            PKCECodeChallenge::S256(value) | PKCECodeChallenge::Plain(value) => value,
        }
    }
}

#[derive(Serialize)]
struct PKCEGrantParams {
    auth_code: String,
    code_verifier: String,
}

#[derive(Serialize, Deserialize)]
struct Password {
    email: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct RefreshToken {
    refresh_token: String,
}

impl Supabase {
    /// Validate a Jwt authorization token and return its Claims if successful
    pub async fn jwt_valid(&self, jwt: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        self.custom_jwt_valid::<Claims>(jwt).await
    }

    /// Validate a Jwt authorization token and return its Custom Claims if successful
    pub async fn custom_jwt_valid<T>(&self, jwt: &str) -> Result<T, jsonwebtoken::errors::Error>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut validation = Validation::new(Algorithm::HS256);
        // User's "audience" field marked as deprecated so we skip its validation
        validation.validate_aud = false;

        match decode::<T>(jwt, &self.jwt_decoding_key, &validation) {
            Ok(token_data) => Ok(token_data.claims),
            Err(err) => Err(err),
        }
    }

    pub async fn sign_in_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<AccessToken, Error> {
        let request_url: String = format!("{}/auth/v1/token?grant_type=password", self.url);
        let response = self
            .client
            .post(&request_url)
            .json(&Password {
                email: email.to_string(),
                password: password.to_string(),
            })
            .send()
            .await;
        parse_auth_response::<AccessToken>(response).await
    }

    // This test will fail unless you disable "Enable automatic reuse detection" in Supabase
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<AccessToken, Error> {
        let request_url: String = format!("{}/auth/v1/token?grant_type=refresh_token", self.url);
        let response = self
            .client
            .post(&request_url)
            .json(&RefreshToken {
                refresh_token: refresh_token.to_string(),
            })
            .send()
            .await;
        parse_auth_response::<AccessToken>(response).await
    }

    pub async fn logout(&self, token: String) -> Result<(), Error> {
        let request_url: String = format!("{}/auth/v1/logout", self.url);
        let response = self
            .client
            .post(&request_url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(handle_response_error);

        // Handling Logout special case
        match response {
            Ok(res) if res.status().as_u16() > 399 => {
                let res_status_code = res.status().as_u16();
                match res.json::<AuthError>().await {
                    Ok(res) => Err(Error {
                        http_status: res_status_code,
                        kind: ErrorKind::Auth(AuthError { ..res }),
                    }),
                    Err(e) => Err(auth_error(
                        500,
                        &format!("Error deserializing error: {e:?}"),
                    )),
                }
            }
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub async fn signup_email_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<AccessToken, Error> {
        let request_url: String = format!("{}/auth/v1/signup", self.url);
        let response = self
            .client
            .post(&request_url)
            .json(&Password {
                email: email.to_string(),
                password: password.to_string(),
            })
            .send()
            .await;
        parse_auth_response::<AccessToken>(response).await
    }

    /// Fetch the latest user account information
    pub async fn get_user(&self, token: &str) -> Result<User, Error> {
        let request_url: String = format!("{}/auth/v1/user", self.url);
        let response = self
            .client
            .get(&request_url)
            .bearer_auth(token.to_owned())
            .send()
            .await;
        parse_auth_response::<User>(response).await
    }

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

fn auth_error(code: u16, msg: &str) -> Error {
    Error {
        http_status: code,
        kind: ErrorKind::Auth(AuthError {
            code: Some(code),
            msg: Some(msg.to_string()),
            ..Default::default()
        }),
    }
}

fn handle_response_error(error: reqwest::Error) -> Error {
    match error.status() {
        Some(status) => auth_error(
            status.as_u16(),
            &format!("An unexpected error occurred: {error:?}"),
        ),
        None => auth_error(
            500,
            &format!(
                "Ensure the client is initialized correctly \
                            and the environment variables are properly set: \
                            SUPABASE_URL, SUPABASE_API_KEY, SUPABASE_JWT_SECRET. \
                        error: {error:?}"
            ),
        ),
    }
}

/// Parse the response into one of the types defined in the `schema` module
async fn parse_auth_response<T>(response: Result<Response, reqwest::Error>) -> Result<T, Error>
where
    T: serde::de::DeserializeOwned,
{
    match response {
        Ok(res) if res.status().as_u16() > 399 => {
            let res_status_code = res.status().as_u16();
            match res.json::<AuthError>().await {
                Ok(res) => Err(Error {
                    http_status: res_status_code,
                    kind: ErrorKind::Auth(AuthError { ..res }),
                }),
                Err(e) => Err(auth_error(
                    500,
                    &format!("Error deserializing error: {e:?}"),
                )),
            }
        }
        Ok(res) => match res.json::<T>().await {
            Ok(value) => Ok(value),
            Err(e) => Err(auth_error(
                500,
                &format!("Error deserializing response: {e:?}"),
            )),
        },

        Err(e) => Err(handle_response_error(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::AccessToken;

    async fn client() -> Supabase {
        Supabase::new(None, None, None)
    }

    async fn sign_in_password() -> Result<AccessToken, Error> {
        let client: Supabase = client().await;

        let test_email: String =
            std::env::var("SUPABASE_TEST_EMAIL").unwrap_or_else(|_| String::new());
        let test_pass: String =
            std::env::var("SUPABASE_TEST_PASS").unwrap_or_else(|_| String::new());
        client.sign_in_password(&test_email, &test_pass).await
    }

    #[tokio::test]
    async fn test_token_with_password() {
        let response: AccessToken = sign_in_password().await.unwrap();

        let token: &str = response.access_token.as_str();
        let refresh_token: &str = response.refresh_token.as_str();

        assert!(!token.is_empty());
        assert!(!refresh_token.is_empty());
    }

    #[tokio::test]
    async fn test_refresh() {
        let response = sign_in_password().await.unwrap();

        let refresh_token: &str = response.refresh_token.as_str();

        let response = client().await.refresh_token(refresh_token).await;
        match response {
            Ok(res) => {
                let token: &str = res.access_token.as_str();

                assert!(!token.is_empty());
            }
            Err(_) => {
                println!(
                "Skipping test_refresh() because automatic reuse detection is enabled in Supabase"
            );
                return;
            }
        }
    }

    #[tokio::test]
    async fn test_logout() {
        let response: AccessToken = sign_in_password().await.unwrap();

        let access_token: &str = response.access_token.as_str();
        let mut client: Supabase = client().await;
        client.bearer_token = Some(access_token.to_string());

        let response = client.logout(client.bearer_token.clone().unwrap()).await;

        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn test_signup_email_password() {
        use rand::{distributions::Alphanumeric, thread_rng, Rng};

        let client: Supabase = client().await;

        let rand_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();

        let random_email: String = format!("{}@a-rust-domain-that-does-not-exist.com", rand_string);
        let random_pass: String = rand_string;

        let test_email: String = random_email;
        let test_pass: String = random_pass;
        let response = client.signup_email_password(&test_email, &test_pass).await;

        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn test_authenticate_token() {
        let client: Supabase = client().await;
        let response: AccessToken = sign_in_password().await.unwrap();

        let token: &str = response.access_token.as_str();

        let response = client.jwt_valid(token).await;

        assert!(response.is_ok());
    }
}
