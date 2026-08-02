use std::{
    error::Error,
    fmt::{Display, Error as FmtError, Formatter},
};

/// An error code reported by the `siteverify` API.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReCaptchaErrorCode {
    /// The secret key is not set.
    MissingInputSecret,
    /// The secret key is invalid or malformed.
    InvalidInputSecret,
    /// The reCAPTCHA token is not set.
    MissingInputResponse,
    /// The reCAPTCHA token is invalid or malformed.
    InvalidInputResponse,
    /// The request is invalid or malformed.
    BadRequest,
    /// The reCAPTCHA token is no longer valid, because it is either too old or has been used before.
    TimeoutOrDuplicate,
    /// An error code this crate does not know about.
    Other(String),
}

impl ReCaptchaErrorCode {
    /// Return this error code as the string the `siteverify` API uses for it.
    #[inline]
    pub fn as_str(&self) -> &str {
        match self {
            ReCaptchaErrorCode::MissingInputSecret => "missing-input-secret",
            ReCaptchaErrorCode::InvalidInputSecret => "invalid-input-secret",
            ReCaptchaErrorCode::MissingInputResponse => "missing-input-response",
            ReCaptchaErrorCode::InvalidInputResponse => "invalid-input-response",
            ReCaptchaErrorCode::BadRequest => "bad-request",
            ReCaptchaErrorCode::TimeoutOrDuplicate => "timeout-or-duplicate",
            ReCaptchaErrorCode::Other(code) => code.as_str(),
        }
    }
}

impl From<String> for ReCaptchaErrorCode {
    #[inline]
    fn from(code: String) -> Self {
        match code.as_str() {
            "missing-input-secret" => ReCaptchaErrorCode::MissingInputSecret,
            "invalid-input-secret" => ReCaptchaErrorCode::InvalidInputSecret,
            "missing-input-response" => ReCaptchaErrorCode::MissingInputResponse,
            "invalid-input-response" => ReCaptchaErrorCode::InvalidInputResponse,
            "bad-request" => ReCaptchaErrorCode::BadRequest,
            "timeout-or-duplicate" => ReCaptchaErrorCode::TimeoutOrDuplicate,
            _ => ReCaptchaErrorCode::Other(code),
        }
    }
}

impl From<&str> for ReCaptchaErrorCode {
    #[inline]
    fn from(code: &str) -> Self {
        ReCaptchaErrorCode::from(code.to_string())
    }
}

impl Display for ReCaptchaErrorCode {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Errors of the `ReCaptcha` struct.
pub enum ReCaptchaError {
    /// The `siteverify` API rejected the verification and reported these error codes.
    ErrorCodes(Vec<ReCaptchaErrorCode>),
    /// The `siteverify` API answered with an unexpected status code.
    UnexpectedStatusCode(u16),
    /// The request to the `siteverify` API could not be completed.
    Request(String),
    /// The answer of the `siteverify` API could not be understood.
    UnexpectedResponse(String),
}

impl ReCaptchaError {
    /// Return the error codes the `siteverify` API reported, which is empty for every other kind of error.
    #[inline]
    pub fn error_codes(&self) -> &[ReCaptchaErrorCode] {
        match self {
            ReCaptchaError::ErrorCodes(error_codes) => error_codes.as_slice(),
            _ => &[],
        }
    }
}

impl Display for ReCaptchaError {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        match self {
            ReCaptchaError::ErrorCodes(error_codes) => {
                f.write_str("The `siteverify` API reported the error codes:")?;

                for error_code in error_codes {
                    f.write_str(" ")?;
                    Display::fmt(error_code, f)?;
                }

                Ok(())
            },
            ReCaptchaError::UnexpectedStatusCode(status_code) => {
                write!(f, "The response status code of the `siteverify` API is {status_code}.")
            },
            ReCaptchaError::Request(text) | ReCaptchaError::UnexpectedResponse(text) => {
                f.write_str(text)
            },
        }
    }
}

impl Error for ReCaptchaError {}
