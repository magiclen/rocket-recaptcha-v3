use std::error::Error;
use std::fmt::{Display, Error as FmtError, Formatter};

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

impl Display for ReCaptchaError {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        match self {
            ReCaptchaError::InvalidInputSecret => f.write_str("The secret key is invalid."),
            ReCaptchaError::InvalidReCaptchaToken => f.write_str("The reCAPTCHA token is invalid."),
            ReCaptchaError::TimeoutOrDuplicate => {
                f.write_str("The reCAPTCHA token is no longer valid.")
            }
            ReCaptchaError::InternalError(text) => f.write_str(text),
        }
    }
}

impl Error for ReCaptchaError {}
