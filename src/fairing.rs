use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Build, Rocket};

use crate::{ReCaptcha, ReCaptchaVariant, V2, V3};

const FAIRING_NAME: &str = "reCAPTCHA v3";

#[derive(Debug)]
pub struct ReCaptchaFairing<V: ReCaptchaVariant = V3> {
    variant: V,
}

impl ReCaptchaFairing<V3> {
    pub(crate) fn new() -> ReCaptchaFairing<V3> {
        ReCaptchaFairing {
            variant: V3,
        }
    }
}

impl ReCaptchaFairing<V2> {
    pub(crate) fn new() -> ReCaptchaFairing<V2> {
        ReCaptchaFairing {
            variant: V2,
        }
    }
}

#[rocket::async_trait]
impl<V: ReCaptchaVariant> Fairing for ReCaptchaFairing<V> {
    fn info(&self) -> Info {
        Info {
            name: FAIRING_NAME,
            kind: Kind::Ignite,
        }
    }

    async fn on_ignite(&self, rocket: Rocket<Build>) -> Result<Rocket<Build>, Rocket<Build>> {
        let recaptcha = rocket
            .figment()
            .find_value("recaptcha")
            .ok()
            .and_then(|recaptcha| recaptcha.into_dict());

        match recaptcha {
            Some(recaptcha) => {
                let v = recaptcha.get(self.variant.get_version_str()).and_then(|v| v.as_dict());

                match v {
                    Some(v) => {
                        let secret_key =
                            v.get("secret_key").and_then(|secret_key| secret_key.as_str());

                        match secret_key {
                            Some(secret_key) => {
                                let html_key =
                                    v.get("html_key").and_then(|html_key| html_key.as_str());

                                let recaptcha =
                                    ReCaptcha::<V>::from_str(html_key, secret_key).unwrap();

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
