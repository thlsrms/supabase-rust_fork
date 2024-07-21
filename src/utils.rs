use crate::errors::{AuthError, Error, ErrorKind, PostgrestError};

pub(crate) enum Parse {
    Auth,
    Postgrest,
}

pub(crate) enum ParsedData<T> {
    Auth(T),
    Postgrest(Vec<T>),
}

impl<T> ParsedData<T> {
    pub fn auth(self) -> Option<T> {
        match self {
            Self::Auth(data) => Some(data),
            _ => None,
        }
    }

    pub fn postgrest(self) -> Option<Vec<T>> {
        match self {
            Self::Postgrest(data) => Some(data),
            _ => None,
        }
    }
}

pub(crate) async fn parse_response<T>(
    response: Result<reqwest::Response, reqwest::Error>,
    kind: Parse,
) -> Result<ParsedData<T>, Error>
where
    T: serde::de::DeserializeOwned,
{
    match response {
        Ok(res) => {
            let res_status_code = res.status().as_u16();
            let body: serde_json::Value = match res.json().await {
                Ok(t) => t,
                Err(e) => {
                    return Err(supabase_error(
                        500,
                        &format!("Error parsing response: {e:?}"),
                        kind,
                    ))
                }
            };

            match kind {
                Parse::Postgrest => {
                    if res_status_code != 200 {
                        return match serde_json::from_value::<PostgrestError>(body) {
                            Ok(err) => Err(Error {
                                http_status: res_status_code,
                                kind: ErrorKind::Postgrest(err),
                            }),
                            Err(e) => Err(supabase_error(
                                500,
                                &format!("Error deserializing error: {e:?}"),
                                kind,
                            )),
                        };
                    }
                }
                Parse::Auth => {
                    if res_status_code > 399 {
                        return match serde_json::from_value::<AuthError>(body) {
                            Ok(res) => Err(Error {
                                http_status: res_status_code,
                                kind: ErrorKind::Auth(AuthError { ..res }),
                            }),
                            Err(e) => Err(supabase_error(
                                500,
                                &format!("Error deserializing error: {e:?}"),
                                kind,
                            )),
                        };
                    }
                }
            }

            if body.is_array() {
                match serde_json::from_value::<Vec<T>>(body) {
                    Ok(t) => Ok(ParsedData::Postgrest(t)), // It may return an empty Vec
                    Err(e) => Err(supabase_error(
                        500,
                        &format!("Error deserializing response: {e:?}"),
                        kind,
                    )),
                }
            } else {
                match serde_json::from_value::<T>(body) {
                    Ok(t) => match kind {
                        Parse::Auth => Ok(ParsedData::Auth(t)),
                        Parse::Postgrest => Ok(ParsedData::Postgrest(vec![t])),
                    },
                    Err(e) => Err(supabase_error(
                        500,
                        &format!("Error deserializing response: {e:?}"),
                        kind,
                    )),
                }
            }
        }

        Err(e) => match e.status() {
            Some(status) => Err(supabase_error(
                status.as_u16(),
                &format!("An unexpected error occurred: {e:?}"),
                kind,
            )),
            None => Err(supabase_error(
                500,
                &format!(
                    "Ensure the client is initialized correctly \
                            and the environment variables are properly set: \
                            SUPABASE_URL, SUPABASE_API_KEY, SUPABASE_JWT_SECRET. \
                        error: {e:?}"
                ),
                kind,
            )),
        },
    }
}

fn supabase_error(code: u16, msg: &str, kind: Parse) -> Error {
    match kind {
        Parse::Auth => Error {
            http_status: code,
            kind: ErrorKind::Auth(AuthError {
                code: Some(code),
                msg: Some(msg.to_string()),
                ..Default::default()
            }),
        },
        Parse::Postgrest => Error {
            http_status: code,
            kind: ErrorKind::Postgrest(PostgrestError {
                code: code.to_string(),
                message: msg.to_string(),
                ..Default::default()
            }),
        },
    }
}
