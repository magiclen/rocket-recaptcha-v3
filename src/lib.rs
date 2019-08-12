/*!
# reCAPTCHA v3 for Rocket Framework

This crate can help you use reCAPTCHA v3 in your Rocket web application.

See `Rocket.toml` and `examples`.
*/

#[macro_use]
extern crate validators;

#[macro_use]
extern crate lazy_static;
extern crate regex;

extern crate easy_http_request;

extern crate chrono;

extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

extern crate rocket;

extern crate rocket_client_addr;

mod verification;
mod errors;
mod fairing;

use std::collections::HashMap;
use std::str::FromStr;

use easy_http_request::HttpRequest;

use validators::ValidatedCustomizedStringError;

use regex::Regex;

use chrono::prelude::*;

pub use rocket_client_addr::ClientRealAddr;

pub use errors::ReCaptchaError;
use fairing::ReCaptchaFairing;

pub use verification::ReCaptchaVerification;
use verification::ReCaptchaVerificationInner;

const API_URL: &str = "https://www.google.com/recaptcha/api/siteverify";

lazy_static! {
    static ref RE_KEY: Regex = {
        Regex::new(r"^[0-9a-zA-Z\-_]{40}$").unwrap()
    };

    static ref RE_TOKEN: Regex = {
        Regex::new(r"^[0-9a-zA-Z\-_]+$").unwrap()
    };
}

validated_customized_regex_string!(pub ReCaptchaKey, ref RE_KEY);
validated_customized_regex_string!(pub ReCaptchaToken, ref RE_TOKEN);

#[derive(Debug, Clone)]
pub struct ReCaptcha {
    html_key: Option<ReCaptchaKey>,
    secret_key: ReCaptchaKey,
}

impl ReCaptcha {
    #[inline]
    pub fn new(html_key: Option<ReCaptchaKey>, secret_key: ReCaptchaKey) -> ReCaptcha {
        ReCaptcha {
            html_key,
            secret_key,
        }
    }

    #[inline]
    pub fn from_str<S1: AsRef<str>, S2: AsRef<str>>(html_key: Option<S1>, secret_key: S2) -> Result<ReCaptcha, ValidatedCustomizedStringError> {
        let html_key = match html_key {
            Some(html_key) => Some(ReCaptchaKey::from_str(html_key.as_ref())?),
            None => None
        };

        let secret_key = ReCaptchaKey::from_str(secret_key.as_ref())?;

        Ok(ReCaptcha {
            html_key,
            secret_key,
        })
    }

    #[inline]
    pub fn from_string<S1: Into<String>, S2: Into<String>>(html_key: Option<S1>, secret_key: S2) -> Result<ReCaptcha, ValidatedCustomizedStringError> {
        let html_key = match html_key {
            Some(html_key) => Some(ReCaptchaKey::from_string(html_key.into())?),
            None => None
        };

        let secret_key = ReCaptchaKey::from_string(secret_key.into())?;

        Ok(ReCaptcha {
            html_key,
            secret_key,
        })
    }

    #[inline]
    pub fn get_html_key_as_str(&self) -> Option<&str> {
        self.html_key.as_ref().map(|k| k.as_str())
    }

    #[inline]
    pub fn get_secret_key_as_str(&self) -> &str {
        self.secret_key.as_str()
    }

    #[inline]
    pub fn fairing() -> ReCaptchaFairing {
        ReCaptchaFairing
    }
}

impl ReCaptcha {
    pub fn verify(&self, recaptcha_token: &ReCaptchaToken, remote_ip: Option<&ClientRealAddr>) -> Result<ReCaptchaVerification, ReCaptchaError> {
        let mut request: HttpRequest<&str, String, &str, &str, &str, &str> = HttpRequest::post_from_url_str(API_URL).unwrap();

        request.query = Some({
            let mut map = HashMap::new();

            map.insert("secret", self.get_secret_key_as_str().to_string());
            map.insert("response", recaptcha_token.as_str().to_string());

            if let Some(remote_ip) = remote_ip {
                map.insert("remoteip", remote_ip.ip.to_string());
            }

            map
        });

        let response = request.send().map_err(|err| ReCaptchaError::InternalError(format!("{:?}", err)))?;

        if response.status_code == 200 {
            let body = response.body;

            let result: ReCaptchaVerificationInner = serde_json::from_slice(&body).map_err(|err| ReCaptchaError::InternalError(err.to_string()))?;

            if result.success {
                let score = result.score.ok_or(ReCaptchaError::InternalError("There is no `score` field.".to_string()))?;
                let action = result.action.ok_or(ReCaptchaError::InternalError("There is no `action` field.".to_string()))?;
                let challenge_ts = result.challenge_ts.ok_or(ReCaptchaError::InternalError("There is no `challenge_ts` field.".to_string()))?;
                let hostname = result.hostname.ok_or(ReCaptchaError::InternalError("There is no `hostname` field.".to_string()))?;

                let challenge_ts = DateTime::from_str(&challenge_ts).map_err(|_| ReCaptchaError::InternalError(format!("The format of the timestamp `{}` is incorrect.", challenge_ts)))?;

                Ok(ReCaptchaVerification {
                    score,
                    action,
                    challenge_ts,
                    hostname,
                })
            } else {
                match result.error_codes {
                    Some(error_codes) => {
                        if error_codes.contains(&"invalid-input-secret".to_string()) {
                            Err(ReCaptchaError::InvalidInputSecret)
                        } else if error_codes.contains(&"invalid-input-response".to_string()) {
                            Err(ReCaptchaError::InvalidReCaptchaToken)
                        } else if error_codes.contains(&"timeout-or-duplicate".to_string()) {
                            Err(ReCaptchaError::TimeoutOrDuplicate)
                        } else {
                            Err(ReCaptchaError::InternalError("No expected error codes.".to_string()))
                        }
                    }
                    None => Err(ReCaptchaError::InternalError("No error codes.".to_string()))
                }
            }
        } else {
            Err(ReCaptchaError::InternalError(format!("The response status code of the `siteverify` API is {}.", response.status_code)))
        }
    }
}