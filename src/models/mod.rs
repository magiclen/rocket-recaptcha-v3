use once_cell::sync::Lazy;
use validators::prelude::*;
use validators_prelude::regex::Regex;

static RE_KEY: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9a-zA-Z\-_]{40}$").unwrap());

#[derive(Debug, Clone, Validator)]
#[validator(regex(regex = RE_KEY))]
pub struct ReCaptchaKey(String);

impl ReCaptchaKey {
    pub fn new(token: String) -> Self {
        ReCaptchaKey(token)
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Clone, Validator)]
#[validator(base64_url(padding(Disallow)))]
pub struct ReCaptchaToken(String);

impl ReCaptchaToken {
    pub fn new(token: String) -> Self {
        ReCaptchaToken(token)
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
