use reqwest::Response;

use crate::errors::{AuthError, Error, ErrorKind};

/// Parse the response into one of the types defined in the `schema` module
pub(crate) async fn parse_auth_response<T>(
    response: Result<Response, reqwest::Error>,
) -> Result<T, Error>
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

pub(crate) fn auth_error(code: u16, msg: &str) -> Error {
    Error {
        http_status: code,
        kind: ErrorKind::Auth(AuthError {
            code: Some(code),
            msg: Some(msg.to_string()),
            ..Default::default()
        }),
    }
}

pub(crate) fn handle_response_error(error: reqwest::Error) -> Error {
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
