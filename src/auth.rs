use jsonwebtoken::{decode, Algorithm, Validation};
use reqwest::Response;
use serde::{Deserialize, Serialize};

use crate::errors::Error;
use crate::schema::{AccessToken, Claims};
use crate::Supabase;

#[derive(Serialize, Deserialize)]
pub struct Password {
    email: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
pub struct RefreshToken {
    refresh_token: String,
}

impl Supabase {
    pub async fn jwt_valid(&self, jwt: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let decoded_token = decode::<Claims>(
            jwt,
            &self.jwt_decoding_key,
            &Validation::new(Algorithm::HS256),
        );


        match decoded_token {
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
            .await;
        parse_auth_response::<()>(response).await
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
}

/// Parse the response into one of the types defined in the `schema` module
async fn parse_auth_response<T>(response: Result<Response, reqwest::Error>) -> Result<T, Error>
where
    T: serde::de::DeserializeOwned,
{
    Ok(
        crate::utils::parse_response(response, crate::utils::Parse::Auth)
            .await?
            .auth()
            .unwrap(),
    )
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

