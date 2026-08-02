reCAPTCHA v3 for Rocket Framework
====================

[![CI](https://github.com/magiclen/rocket-recaptcha-v3/actions/workflows/ci.yml/badge.svg)](https://github.com/magiclen/rocket-recaptcha-v3/actions/workflows/ci.yml)

This crate can help you use reCAPTCHA v3 (v2 is backward compatible) in your Rocket web application.

## Configuration

Put your reCAPTCHA keys in `Rocket.toml`. The `html_key` is optional, and is only needed to render the front-end script.

```toml
[default.recaptcha.v3]
html_key = "6Lf6dLIUAAAAAAxghN7nH6m_yuLfHwdD3N7FpanR"
secret_key = "6Lf6dLIUAAAAAHdJ4e0nsv-8OpFH-7Oad1XQ95rq"
```

## Usage

Attach `ReCaptcha::fairing()` to Rocket, and then every route can take a `&State<ReCaptcha>` to verify tokens with.

```rust
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

reCAPTCHA v2 works the same way. Put the keys under `[default.recaptcha.v2]`, attach `ReCaptcha::fairing_v2()`, and take a `&State<ReCaptcha<V2>>` in your routes.

`ReCaptcha::verify` can also report the client's IP address to Google. See the documentation for an example.

## Crates.io

https://crates.io/crates/rocket-recaptcha-v3

## Documentation

https://docs.rs/rocket-recaptcha-v3

## License

[MIT](LICENSE)
