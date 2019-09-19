use crate::rocket::Rocket;

use crate::rocket::fairing::{Fairing, Info, Kind};

use crate::ReCaptcha;

const FAIRING_NAME: &str = "reCAPTCHA v3";

pub struct ReCaptchaFairing;

impl Fairing for ReCaptchaFairing {
    fn info(&self) -> Info {
        Info {
            name: FAIRING_NAME,
            kind: Kind::Attach,
        }
    }

    fn on_attach(&self, rocket: Rocket) -> Result<Rocket, Rocket> {
        let recaptcha =
            rocket.config().extras.get("recaptcha").and_then(|recaptcha| recaptcha.as_table());

        match recaptcha {
            Some(recaptcha) => {
                let v3 = recaptcha.get("v3").and_then(|v3| v3.as_table());

                match v3 {
                    Some(v3) => {
                        let secret_key =
                            v3.get("secret_key").and_then(|secret_key| secret_key.as_str());

                        match secret_key {
                            Some(secret_key) => {
                                let html_key =
                                    v3.get("html_key").and_then(|html_key| html_key.as_str());

                                let recaptcha = ReCaptcha::from_str(html_key, secret_key).unwrap();

                                Ok(rocket.manage(recaptcha))
                            }
                            None => Err(rocket),
                        }
                    }
                    None => Err(rocket),
                }
            }
            None => Err(rocket),
        }
    }
}
