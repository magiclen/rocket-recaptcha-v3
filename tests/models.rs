use rocket_recaptcha_v3::{
    ReCaptchaErrorCode, ReCaptchaKey, ReCaptchaToken, validators::prelude::*,
};

const HTML_KEY: &str = "6Lf6dLIUAAAAAAxghN7nH6m_yuLfHwdD3N7FpanR";
const TOKEN: &str = "03AGdBq26ZLoBGGe_2NrTb7pOEJ7Zvz9bWmNfMxhAeIzE-VeQyRcM";

const ERROR_CODES: [&str; 6] = [
    "missing-input-secret",
    "invalid-input-secret",
    "missing-input-response",
    "invalid-input-response",
    "bad-request",
    "timeout-or-duplicate",
];

#[test]
fn parse_a_recaptcha_key() {
    assert_eq!(HTML_KEY, ReCaptchaKey::parse_str(HTML_KEY).unwrap().as_str());
}

#[test]
fn reject_a_recaptcha_key_of_the_wrong_length() {
    assert!(ReCaptchaKey::parse_str("6Lf6dLIUAAAAAAxghN7nH6m_yuLfHwdD3N7Fpan").is_err());
}

#[test]
fn parse_a_recaptcha_token() {
    assert_eq!(TOKEN, ReCaptchaToken::parse_str(TOKEN).unwrap().as_str());
}

#[test]
fn map_the_error_codes_of_the_siteverify_api() {
    for code in ERROR_CODES {
        let error_code = ReCaptchaErrorCode::from(code);

        assert_eq!(code, error_code.as_str());
        assert!(!matches!(error_code, ReCaptchaErrorCode::Other(_)));
    }
}

#[test]
fn keep_an_unknown_error_code_as_it_is() {
    assert_eq!(
        ReCaptchaErrorCode::Other(String::from("brand-new-code")),
        ReCaptchaErrorCode::from("brand-new-code")
    );
}
