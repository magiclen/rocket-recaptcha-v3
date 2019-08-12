#[derive(Debug, Clone)]
/// Errors of the `ReCaptcha` struct.
pub enum ReCaptchaError {
    /// The secret key is invalid.
    InvalidInputSecret,
    /// The reCAPTCHA token is invalid.
    InvalidReCaptchaToken,
    /// The reCAPTCHA token is no longer valid.
    TimeoutOrDuplicate,
    /// Errors caused by internal malfunctions.
    InternalError(String),
}