use std::marker::PhantomData;

use rocket::{
    Build, Rocket,
    fairing::{Fairing, Info, Kind},
};

use crate::{ReCaptcha, ReCaptchaVariant, V3};

#[derive(Debug)]
/// A Rocket fairing which reads reCAPTCHA keys from the Rocket configuration and then manages a `ReCaptcha` instance.
pub struct ReCaptchaFairing<V: ReCaptchaVariant = V3> {
    phantom: PhantomData<V>,
}

impl<V: ReCaptchaVariant> ReCaptchaFairing<V> {
    #[inline]
    pub(crate) fn new() -> ReCaptchaFairing<V> {
        ReCaptchaFairing {
            phantom: PhantomData
        }
    }
}

#[rocket::async_trait]
impl<V: ReCaptchaVariant> Fairing for ReCaptchaFairing<V> {
    fn info(&self) -> Info {
        Info {
            name: V::FAIRING_NAME, kind: Kind::Ignite
        }
    }

    async fn on_ignite(&self, rocket: Rocket<Build>) -> Result<Rocket<Build>, Rocket<Build>> {
        let version = V::VERSION_STR;

        let Some(recaptcha) = rocket
            .figment()
            .find_value("recaptcha")
            .ok()
            .and_then(|recaptcha| recaptcha.into_dict())
        else {
            rocket::error!("The `recaptcha` table is not set in the Rocket configuration.");

            return Err(rocket);
        };

        let Some(v) = recaptcha.get(version).and_then(|v| v.as_dict()) else {
            rocket::error!(
                "The `recaptcha.{version}` table is not set in the Rocket configuration."
            );

            return Err(rocket);
        };

        let Some(secret_key) = v.get("secret_key").and_then(|secret_key| secret_key.as_str())
        else {
            rocket::error!(
                "The `recaptcha.{version}.secret_key` value is not set in the Rocket \
                 configuration."
            );

            return Err(rocket);
        };

        let html_key = v.get("html_key").and_then(|html_key| html_key.as_str());

        match ReCaptcha::<V>::parse_str(html_key, secret_key) {
            Ok(recaptcha) => Ok(rocket.manage(recaptcha)),
            Err(error) => {
                rocket::error!("The reCAPTCHA {version} keys are invalid: {error}");

                Err(rocket)
            },
        }
    }
}
