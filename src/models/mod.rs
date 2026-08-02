use std::sync::LazyLock;

use validators::prelude::*;
use validators_prelude::regex::Regex;

static RE_KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-zA-Z\-_]{40}$").unwrap());

#[derive(Debug, Clone, Validator)]
#[validator(regex(regex = RE_KEY))]
pub struct ReCaptchaKey(String);

impl ReCaptchaKey {
    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Clone, Validator)]
#[validator(base64_url(padding(Disallow)))]
pub struct ReCaptchaToken(String);

impl ReCaptchaToken {
    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
