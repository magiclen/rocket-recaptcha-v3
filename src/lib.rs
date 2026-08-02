/*!
# reCAPTCHA v3 for Rocket Framework

This crate can help you use reCAPTCHA v3 (v2 is backward compatible) in your Rocket web application.

## Configuration

Put your reCAPTCHA keys in `Rocket.toml`. The `html_key` is optional, and is only needed to render the front-end script.

```toml
[default.recaptcha.v3]
html_key = "6Lf6dLIUAAAAAAxghN7nH6m_yuLfHwdD3N7FpanR"
secret_key = "6Lf6dLIUAAAAAHdJ4e0nsv-8OpFH-7Oad1XQ95rq"
```

## Usage

Attach [`ReCaptcha::fairing`] to Rocket, and then every route can take a `&State<ReCaptcha>` to verify tokens with.

```rust,no_run
#[macro_use]
extern crate rocket;

use rocket::{State, form::Form};
use rocket_recaptcha_v3::{ReCaptcha, ReCaptchaToken};

#[derive(FromForm)]
struct LoginModel {
    recaptcha_token: ReCaptchaToken,
}

#[get("/login")]
fn login_get(recaptcha: &State<ReCaptcha>) -> String {
    // Render the front-end script with this key.
    recaptcha.html_key().unwrap().as_str().to_string()
}

#[post("/login", data = "<model>")]
async fn login_post(recaptcha: &State<ReCaptcha>, model: Form<LoginModel>) -> &'static str {
    match recaptcha.verify(&model.recaptcha_token, None).await {
        Ok(verification) => {
            if verification.score > 0.7 {
                "Hello, human!"
            } else {
                "You are probably not a human."
            }
        },
        Err(_) => "Please try again.",
    }
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    rocket::build()
        .attach(ReCaptcha::fairing())
        .mount("/", routes![login_get, login_post])
        .launch()
        .await?;

    Ok(())
}
```

## reCAPTCHA v2

reCAPTCHA v2 works the same way. Put the keys under `[default.recaptcha.v2]`, attach [`ReCaptcha::fairing_v2`], and take a `&State<ReCaptcha<V2>>` in your routes. A solved v2 challenge carries no score, so [`ReCaptchaVerification::score`] is always `1.0` for it.

Both fairings can be attached to the same Rocket instance, because `ReCaptcha<V3>` and `ReCaptcha<V2>` are separate types.

## The client's IP address

[`ReCaptcha::verify`] can report the client's IP address to Google along with the token. Pass `None` to leave it out, or a [`ClientIp`] from the re-exported [`rocket_client_addr`] crate, which needs its `ClientIpConfig` in Rocket's managed state.

```rust,no_run
#[macro_use]
extern crate rocket;

use rocket::{State, form::Form};
use rocket_recaptcha_v3::{
    ClientIp, ReCaptcha, ReCaptchaToken,
    rocket_client_addr::{ClientIpConfig, IpCidr},
};

#[derive(FromForm)]
struct LoginModel {
    recaptcha_token: ReCaptchaToken,
}

#[post("/login", data = "<model>")]
async fn login_post(
    recaptcha: &State<ReCaptcha>,
    client_ip: &ClientIp,
    model: Form<LoginModel>,
) -> &'static str {
    match recaptcha.verify(&model.recaptcha_token, Some(client_ip)).await {
        Ok(verification) if verification.score > 0.7 => "Hello, human!",
        Ok(_) => "You are probably not a human.",
        Err(_) => "Please try again.",
    }
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    let client_ip_config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy("10.0.0.0/24".parse::<IpCidr>().unwrap())
        .build()
        .unwrap();

    rocket::build()
        .attach(ReCaptcha::fairing())
        .manage(client_ip_config)
        .mount("/", routes![login_post])
        .launch()
        .await?;

    Ok(())
}
```
*/

mod errors;
mod fairing;
mod models;
mod verification;

use std::{
    borrow::Cow, error::Error, fmt::Debug, marker::PhantomData, sync::LazyLock, time::Duration,
};

pub use chrono;
pub use errors::{ReCaptchaError, ReCaptchaErrorCode};
pub use fairing::ReCaptchaFairing;
pub use models::*;
use reqwest::Client;
pub use rocket_client_addr::{self, ClientIp};
use validators::prelude::*;
pub use validators::{self, errors::RegexError};
pub use verification::ReCaptchaVerification;
use verification::ReCaptchaVerificationInner;

/// The endpoint of the `siteverify` API, which is what a `ReCaptcha` instance uses by default.
pub const API_URL: &str = "https://www.google.com/recaptcha/api/siteverify";

/// An alternative endpoint of the `siteverify` API, for regions where `google.com` cannot be reached.
pub const API_URL_RECAPTCHA_NET: &str = "https://www.recaptcha.net/recaptcha/api/siteverify";

/// A whole request to the `siteverify` API should not outlive a page load, so this is deliberately short.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Every `ReCaptcha` instance shares this client, so that one connection pool serves the whole process.
static DEFAULT_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder().timeout(DEFAULT_TIMEOUT).build().expect("cannot build an HTTP client")
});

mod sealed {
    pub trait Sealed {}
}

/// A version of reCAPTCHA. This trait is sealed, and [`V3`] and [`V2`] are its only implementations.
pub trait ReCaptchaVariant: sealed::Sealed + Debug + Clone + Sync + Send + 'static {
    /// The name of the Rocket configuration table this version reads its keys from.
    const VERSION_STR: &'static str;
    /// The name this version's fairing reports to Rocket.
    const FAIRING_NAME: &'static str;
}

#[derive(Debug, Clone, Copy)]
/// reCAPTCHA v3, which scores a request instead of challenging the user.
pub struct V3;

impl sealed::Sealed for V3 {}

impl ReCaptchaVariant for V3 {
    const FAIRING_NAME: &'static str = "reCAPTCHA v3";
    const VERSION_STR: &'static str = "v3";
}

#[derive(Debug, Clone, Copy)]
/// reCAPTCHA v2, which challenges the user and reports no score.
pub struct V2;

impl sealed::Sealed for V2 {}

impl ReCaptchaVariant for V2 {
    const FAIRING_NAME: &'static str = "reCAPTCHA v2";
    const VERSION_STR: &'static str = "v2";
}

#[derive(Debug, Clone)]
/// A pair of reCAPTCHA keys which can verify reCAPTCHA tokens.
pub struct ReCaptcha<V: ReCaptchaVariant = V3> {
    html_key:   Option<ReCaptchaKey>,
    secret_key: ReCaptchaKey,
    client:     Client,
    api_url:    Cow<'static, str>,
    phantom:    PhantomData<V>,
}

impl<V: ReCaptchaVariant> ReCaptcha<V> {
    #[inline]
    /// You should use the Rocket fairing mechanism instead of invoking this method to create a `ReCaptcha` instance.
    pub fn new(html_key: Option<ReCaptchaKey>, secret_key: ReCaptchaKey) -> ReCaptcha<V> {
        ReCaptcha {
            html_key,
            secret_key,
            client: DEFAULT_CLIENT.clone(),
            api_url: Cow::from(API_URL),
            phantom: PhantomData,
        }
    }

    #[inline]
    /// You should use the Rocket fairing mechanism instead of invoking this method to create a `ReCaptcha` instance.
    pub fn parse_str<S1: AsRef<str>, S2: AsRef<str>>(
        html_key: Option<S1>,
        secret_key: S2,
    ) -> Result<ReCaptcha<V>, RegexError> {
        #[allow(clippy::manual_map)]
        let html_key = match html_key {
            Some(html_key) => Some(ReCaptchaKey::parse_str(html_key.as_ref())?),
            None => None,
        };

        let secret_key = ReCaptchaKey::parse_str(secret_key.as_ref())?;

        Ok(ReCaptcha::<V>::new(html_key, secret_key))
    }

    #[inline]
    /// You should use the Rocket fairing mechanism instead of invoking this method to create a `ReCaptcha` instance.
    pub fn parse_string<S1: Into<String>, S2: Into<String>>(
        html_key: Option<S1>,
        secret_key: S2,
    ) -> Result<ReCaptcha<V>, RegexError> {
        #[allow(clippy::manual_map)]
        let html_key = match html_key {
            Some(html_key) => Some(ReCaptchaKey::parse_string(html_key.into())?),
            None => None,
        };

        let secret_key = ReCaptchaKey::parse_string(secret_key.into())?;

        Ok(ReCaptcha::<V>::new(html_key, secret_key))
    }

    #[inline]
    /// Return the key the front-end script needs, which is not set unless the configuration provides it.
    pub fn html_key(&self) -> Option<&ReCaptchaKey> {
        self.html_key.as_ref()
    }

    #[inline]
    /// Return the key the `siteverify` API is called with.
    pub fn secret_key(&self) -> &ReCaptchaKey {
        &self.secret_key
    }

    #[inline]
    /// Return the endpoint of the `siteverify` API this instance calls.
    pub fn api_url(&self) -> &str {
        self.api_url.as_ref()
    }

    #[inline]
    /// Call another endpoint of the `siteverify` API, such as [`API_URL_RECAPTCHA_NET`].
    pub fn set_api_url<S: Into<Cow<'static, str>>>(&mut self, api_url: S) {
        self.api_url = api_url.into();
    }

    #[inline]
    /// Call the `siteverify` API with your own HTTP client, to control its timeout or its proxy.
    pub fn set_client(&mut self, client: Client) {
        self.client = client;
    }
}

impl ReCaptcha {
    #[inline]
    /// Create a `ReCaptchaFairing<V3>` instance to load reCAPTCHA v3 keys. It will mount a `ReCaptcha<V3>` (`ReCaptcha`) instance on Rocket.
    pub fn fairing() -> ReCaptchaFairing<V3> {
        ReCaptchaFairing::<V3>::new()
    }

    #[inline]
    /// Create a `ReCaptchaFairing<V2>` instance to load reCAPTCHA v2 keys. It will mount a `ReCaptcha<V2>` instance on Rocket.
    pub fn fairing_v2() -> ReCaptchaFairing<V2> {
        ReCaptchaFairing::<V2>::new()
    }
}

impl<V: ReCaptchaVariant> ReCaptcha<V> {
    /// Ask the `siteverify` API whether a reCAPTCHA token is genuine.
    ///
    /// Reporting `remote_ip` is optional, and lets Google take the client's address into account.
    pub async fn verify(
        &self,
        recaptcha_token: &ReCaptchaToken,
        remote_ip: Option<&ClientIp>,
    ) -> Result<ReCaptchaVerification, ReCaptchaError> {
        // The parameters go into the request body, so that the secret key never reaches a URL.
        let mut form: Vec<(&str, Cow<str>)> = Vec::with_capacity(3);

        form.push(("secret", Cow::from(self.secret_key.as_str())));
        form.push(("response", Cow::from(recaptcha_token.as_str())));

        if let Some(remote_ip) = remote_ip {
            form.push(("remoteip", Cow::from(remote_ip.ip().to_string())));
        }

        let response = self
            .client
            .post(self.api_url.as_ref())
            .form(&form)
            .send()
            .await
            .map_err(|error| ReCaptchaError::Request(describe_error(&error)))?;

        let status = response.status();

        if !status.is_success() {
            return Err(ReCaptchaError::UnexpectedStatusCode(status.as_u16()));
        }

        let result: ReCaptchaVerificationInner = response
            .json()
            .await
            .map_err(|error| ReCaptchaError::UnexpectedResponse(describe_error(&error)))?;

        if !result.success {
            return Err(ReCaptchaError::ErrorCodes(
                result
                    .error_codes
                    .unwrap_or_default()
                    .into_iter()
                    .map(ReCaptchaErrorCode::from)
                    .collect(),
            ));
        }

        let challenge_ts = result.challenge_ts.ok_or_else(|| {
            ReCaptchaError::UnexpectedResponse("There is no `challenge_ts` field.".to_string())
        })?;

        let hostname = result.hostname.ok_or_else(|| {
            ReCaptchaError::UnexpectedResponse("There is no `hostname` field.".to_string())
        })?;

        Ok(ReCaptchaVerification {
            // reCAPTCHA v2 scores nothing, so a challenge it accepted is fully human.
            score: result.score.unwrap_or(1.0),
            action: result.action,
            challenge_ts,
            hostname,
        })
    }
}

/// Flatten an error and its sources into one line, because only the message survives into a `ReCaptchaError`.
fn describe_error(error: &dyn Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();

    while let Some(error) = source {
        text.push_str(": ");
        text.push_str(&error.to_string());

        source = error.source();
    }

    text
}
