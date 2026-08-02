use std::sync::LazyLock;

use validators::prelude::*;
use validators_prelude::regex::Regex;

static RE_KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-zA-Z\-_]{40}$").unwrap());

#[derive(Debug, Clone, Validator)]
#[validator(regex(regex = RE_KEY))]
/// A reCAPTCHA key, which is 40 characters of `0-9`, `a-z`, `A-Z`, `-` and `_`.
pub struct ReCaptchaKey(String);

impl ReCaptchaKey {
    /// Return this key as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Clone, Validator)]
#[validator(base64_url(padding(Disallow)))]
/// A reCAPTCHA token, which a client obtains from the reCAPTCHA front-end script and then sends to the server.
pub struct ReCaptchaToken(String);

impl ReCaptchaToken {
    /// Return this token as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
