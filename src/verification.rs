use crate::chrono::prelude::*;

#[derive(Debug, Clone)]
pub struct ReCaptchaVerification {
    /// The score for this verification (0.0 - 1.0). The higher the more human.
    pub score: f64,
    /// The action name for this verification.
    pub action: String,
    /// The timestamp of the challenge load.
    pub challenge_ts: DateTime<Utc>,
    /// The hostname of the site where the reCAPTCHA was solved.
    pub hostname: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ReCaptchaVerificationInner {
    pub(crate) success: bool,
    pub(crate) score: Option<f64>,
    pub(crate) action: Option<String>,
    pub(crate) challenge_ts: Option<String>,
    pub(crate) hostname: Option<String>,
    #[serde(rename = "error-codes")]
    pub(crate) error_codes: Option<Vec<String>>,
}
