/*!
# reCAPTCHA v3 for Rocket Framework

This crate can help you use reCAPTCHA v3 in your Rocket web application.

See `Rocket.toml` and `examples`.
*/

#[macro_use]
extern crate validators_derive;

extern crate validators;

extern crate easy_http_request;

extern crate chrono;

extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

extern crate rocket;

extern crate rocket_client_addr;

mod errors;
mod fairing;
mod models;
mod verification;

use std::collections::HashMap;
use std::marker::PhantomData;
use std::str::FromStr;

use easy_http_request::HttpRequest;

use chrono::prelude::*;

pub use rocket_client_addr::ClientRealAddr;

pub use errors::ReCaptchaError;
use fairing::ReCaptchaFairing;

pub use verification::ReCaptchaVerification;
use verification::ReCaptchaVerificationInner;

use validators::prelude::*;
use validators::RegexError;

pub use models::*;

const API_URL: &str = "https://www.google.com/recaptcha/api/siteverify";

pub trait ReCaptchaVariant: Sync + Send + 'static {
    fn get_version_str(&self) -> &'static str;
}

#[derive(Debug, Clone, Copy)]
pub struct V3;

impl ReCaptchaVariant for V3 {
    #[inline]
    fn get_version_str(&self) -> &'static str {
        "v3"
    }
}

#[derive(Debug, Clone, Copy)]
pub struct V2;

impl ReCaptchaVariant for V2 {
    #[inline]
    fn get_version_str(&self) -> &'static str {
        "v2"
    }
}

#[derive(Debug, Clone)]
pub struct ReCaptcha<V: ReCaptchaVariant = V3> {
    html_key: Option<ReCaptchaKey>,
    secret_key: ReCaptchaKey,
    phantom: PhantomData<V>,
}

impl<V: ReCaptchaVariant> ReCaptcha<V> {
    #[inline]
    /// You should use the Rocket fairing mechanism instead of invoking this method to create a `ReCaptcha` instance.
    pub fn new(html_key: Option<ReCaptchaKey>, secret_key: ReCaptchaKey) -> ReCaptcha<V> {
        ReCaptcha {
            html_key,
            secret_key,
            phantom: PhantomData,
        }
    }

    #[inline]
    /// You should use the Rocket fairing mechanism instead of invoking this method to create a `ReCaptcha` instance.
    pub fn from_str<S1: AsRef<str>, S2: AsRef<str>>(
        html_key: Option<S1>,
        secret_key: S2,
    ) -> Result<ReCaptcha<V>, RegexError> {
        #[allow(clippy::manual_map)]
        let html_key = match html_key {
            Some(html_key) => Some(ReCaptchaKey::parse_str(html_key.as_ref())?),
            None => None,
        };

        let secret_key = ReCaptchaKey::parse_str(secret_key.as_ref())?;

        Ok(ReCaptcha::<V>::new(html_key, secret_key))
    }

    #[inline]
    /// You should use the Rocket fairing mechanism instead of invoking this method to create a `ReCaptcha` instance.
    pub fn from_string<S1: Into<String>, S2: Into<String>>(
        html_key: Option<S1>,
        secret_key: S2,
    ) -> Result<ReCaptcha<V>, RegexError> {
        #[allow(clippy::manual_map)]
        let html_key = match html_key {
            Some(html_key) => Some(ReCaptchaKey::parse_string(html_key.into())?),
            None => None,
        };

        let secret_key = ReCaptchaKey::parse_string(secret_key.into())?;

        Ok(ReCaptcha::<V>::new(html_key, secret_key))
    }

    #[inline]
    pub fn get_html_key_as_str(&self) -> Option<&str> {
        self.html_key.as_ref().map(|k| k.as_str())
    }

    #[inline]
    pub fn get_secret_key_as_str(&self) -> &str {
        self.secret_key.as_str()
    }
}

impl ReCaptcha {
    #[inline]
    /// Create a `ReCaptchaFairing<V3>` instance to load reCAPTCHA v3 keys. It will mount a `ReCaptcha<V3>` (`ReCaptcha`) instance on Rocket.
    pub fn fairing() -> ReCaptchaFairing<V3> {
        ReCaptchaFairing::<V3>::new()
    }

    #[inline]
    /// Create a `ReCaptchaFairing<V2>` instance to load reCAPTCHA v2 keys. It will mount a `ReCaptcha<V2>` instance on Rocket.
    pub fn fairing_v2() -> ReCaptchaFairing<V2> {
        ReCaptchaFairing::<V2>::new()
    }
}

impl<V: ReCaptchaVariant> ReCaptcha<V> {
    pub fn verify(
        &self,
        recaptcha_token: &ReCaptchaToken,
        remote_ip: Option<&ClientRealAddr>,
    ) -> Result<ReCaptchaVerification, ReCaptchaError> {
        let mut request: HttpRequest<&str, String, &str, &str, &str, &str> =
            HttpRequest::post_from_url_str(API_URL).unwrap();

        request.query = Some({
            let mut map = HashMap::new();

            map.insert("secret", self.get_secret_key_as_str().to_string());
            map.insert("response", recaptcha_token.as_str().to_string());

            if let Some(remote_ip) = remote_ip {
                map.insert("remoteip", remote_ip.ip.to_string());
            }

            map
        });

        let response =
            request.send().map_err(|err| ReCaptchaError::InternalError(format!("{:?}", err)))?;

        if response.status_code == 200 {
            let body = response.body;

            let result: ReCaptchaVerificationInner = serde_json::from_slice(&body)
                .map_err(|err| ReCaptchaError::InternalError(err.to_string()))?;

            if result.success {
                let score = result.score.unwrap_or(1.0);
                let action = result.action;
                let challenge_ts = result.challenge_ts.ok_or_else(|| {
                    ReCaptchaError::InternalError("There is no `challenge_ts` field.".to_string())
                })?;
                let hostname = result.hostname.ok_or_else(|| {
                    ReCaptchaError::InternalError("There is no `hostname` field.".to_string())
                })?;

                let challenge_ts = DateTime::from_str(&challenge_ts).map_err(|_| {
                    ReCaptchaError::InternalError(format!(
                        "The format of the timestamp `{}` is incorrect.",
                        challenge_ts
                    ))
                })?;

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
                            Err(ReCaptchaError::InternalError(
                                "No expected error codes.".to_string(),
                            ))
                        }
                    }
                    None => Err(ReCaptchaError::InternalError("No error codes.".to_string())),
                }
            }
        } else {
            Err(ReCaptchaError::InternalError(format!(
                "The response status code of the `siteverify` API is {}.",
                response.status_code
            )))
        }
    }
}
