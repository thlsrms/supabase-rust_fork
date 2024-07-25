use crate::errors::{Error, ErrorKind, PostgrestError};

/// Re-export of `serde_json`'s `from_value` function
pub fn parse_value<T>(user_metadata: serde_json::Value) -> Result<T, serde_json::error::Error>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value::<T>(user_metadata)
}

/// Parse the Postgrest response.
/// It requires a generic type that implements the `serde::Deserialize` trait.
pub async fn parse_response<T>(
    response: Result<reqwest::Response, reqwest::Error>,
) -> Result<Vec<T>, Error>
where
    T: serde::de::DeserializeOwned,
{
    fn supabase_error(code: u16, msg: &str) -> Error {
        Error {
            http_status: code,
            kind: ErrorKind::Postgrest(PostgrestError {
                code: code.to_string(),
                message: msg.to_string(),
                ..Default::default()
            }),
        }
    }

    match response {
        Ok(res) => {
            let res_status_code = res.status().as_u16();
            let body: serde_json::Value = match res.json().await {
                Ok(t) => t,
                Err(e) => {
                    return Err(supabase_error(
                        500,
                        &format!("Error parsing response: {e:?}"),
                    ))
                }
            };

            if res_status_code > 299 {
                return match serde_json::from_value::<PostgrestError>(body) {
                    Ok(err) => Err(Error {
                        http_status: res_status_code,
                        kind: ErrorKind::Postgrest(err),
                    }),
                    Err(e) => Err(supabase_error(
                        500,
                        &format!("Error deserializing error: {e:?}"),
                    )),
                };
            }

            if body.is_array() {
                match serde_json::from_value::<Vec<T>>(body) {
                    Ok(t) => Ok(t), // It may return an empty Vec
                    Err(e) => Err(supabase_error(
                        500,
                        &format!("Error deserializing response: {e:?}"),
                    )),
                }
            } else {
                match serde_json::from_value::<T>(body) {
                    Ok(t) => Ok(vec![t]),
                    Err(e) => Err(supabase_error(
                        500,
                        &format!("Error deserializing response: {e:?}"),
                    )),
                }
            }
        }

        Err(e) => match e.status() {
            Some(status) => Err(supabase_error(
                status.as_u16(),
                &format!("An unexpected error occurred: {e:?}"),
            )),
            None => Err(supabase_error(
                500,
                &format!(
                    "Ensure the client is initialized correctly \
                            and the environment variables are properly set: \
                            SUPABASE_URL, SUPABASE_API_KEY, SUPABASE_JWT_SECRET. \
                        error: {e:?}"
                ),
            )),
        },
    }
}
