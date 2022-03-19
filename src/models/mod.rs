use validators::prelude::*;

use validators_prelude::regex::Regex;

use once_cell::sync::Lazy;

static RE_KEY: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9a-zA-Z\-_]{40}$").unwrap());

#[derive(Debug, Clone, Validator)]
#[validator(regex(RE_KEY))]
pub struct ReCaptchaKey(String);

impl ReCaptchaKey {
    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Clone, Validator)]
#[validator(base64_url(padding(NotAllow)))]
pub struct ReCaptchaToken(String);

impl ReCaptchaToken {
    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
