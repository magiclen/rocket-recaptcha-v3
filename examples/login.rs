#[macro_use]
extern crate rocket_include_tera;

#[macro_use]
extern crate validators_derive;

extern crate validators;

extern crate once_cell;

#[macro_use]
extern crate rocket;

extern crate rocket_recaptcha_v3;

use std::collections::HashMap;

use rocket::form::{self, Form};
use rocket::response::Redirect;
use rocket::State;

use rocket_include_tera::{EtagIfNoneMatch, TeraContextManager, TeraResponse};
use rocket_recaptcha_v3::{ReCaptcha, ReCaptchaToken, V2};

use validators::prelude::*;
use validators_prelude::regex::Regex;

use once_cell::sync::Lazy;

static RE_USERNAME: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\w{1,30}$").unwrap());
static RE_PASSWORD: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[\S ]{8,}$").unwrap());

#[derive(Debug, Clone, Validator)]
#[validator(regex(RE_USERNAME))]
pub struct Username(String);

#[derive(Debug, Clone, Validator)]
#[validator(regex(RE_PASSWORD))]
pub struct Password(String);

#[derive(Debug, FromForm)]
struct LoginModel<'v> {
    username: form::Result<'v, Username>,
    password: form::Result<'v, Password>,
    recaptcha_token: form::Result<'v, ReCaptchaToken>,
}

#[get("/login")]
fn login_get(
    cm: State<TeraContextManager>,
    etag_if_none_match: &EtagIfNoneMatch,
    recaptcha: State<ReCaptcha>,
) -> TeraResponse {
    tera_response_cache!(cm, etag_if_none_match, "login", {
        println!("Generate login and cache it...");

        let mut map = HashMap::new();

        map.insert("recaptcha_key", recaptcha.get_html_key_as_str().unwrap());

        tera_response!(cm, EtagIfNoneMatch::default(), "login", &map)
    })
}

#[post("/login", data = "<model>")]
async fn login_post(
    cm: State<'_, TeraContextManager>,
    etag_if_none_match: &EtagIfNoneMatch<'_>,
    recaptcha: State<'_, ReCaptcha>,
    model: Form<LoginModel<'_>>,
) -> Result<Redirect, TeraResponse> {
    let mut map = HashMap::new();

    map.insert("recaptcha_key", recaptcha.get_html_key_as_str().unwrap());

    let username = model.username.as_ref().ok();

    match username {
        Some(username) => {
            let password = model.password.as_ref().ok();

            match password {
                Some(password) => {
                    let recaptcha_token = model.recaptcha_token.as_ref().ok();

                    match recaptcha_token {
                        Some(recaptcha_token) => {
                            match recaptcha.verify(recaptcha_token, None).await {
                                Ok(verification) => {
                                    if verification.score > 0.7 {
                                        // Verify the username/password here
                                        if username.0 == "magiclen" && password.0 == "12345678" {
                                            map.insert(
                                                "message",
                                                "Login successfully, but not implement anything.",
                                            );
                                        } else {
                                            map.insert("message", "Invalid username or password.");
                                        }
                                    } else {
                                        map.insert("message", "You are probably not a human.");
                                    }
                                }
                                Err(_) => {
                                    map.insert("message", "Please try again.");
                                }
                            }
                        }
                        None => {
                            map.insert(
                                "message",
                                "The format of your reCAPTCHA token is incorrect.",
                            );
                        }
                    }
                }
                None => {
                    map.insert("message", "The format of your password is incorrect.");
                }
            }
        }
        None => {
            map.insert("message", "The format of your username is incorrect.");
        }
    }

    Err(tera_response!(cm, etag_if_none_match, "login", &map))
}

#[get("/login-v2")]
fn login_v2_get(
    cm: State<TeraContextManager>,
    etag_if_none_match: &EtagIfNoneMatch,
    recaptcha: State<ReCaptcha<V2>>,
) -> TeraResponse {
    tera_response_cache!(cm, etag_if_none_match, "login_v2", {
        println!("Generate login-v2 and cache it...");

        let mut map = HashMap::new();

        map.insert("recaptcha_key", recaptcha.get_html_key_as_str().unwrap());

        tera_response!(cm, EtagIfNoneMatch::default(), "login_v2", &map)
    })
}

#[post("/login-v2", data = "<model>")]
async fn login_v2_post(
    cm: State<'_, TeraContextManager>,
    recaptcha: State<'_, ReCaptcha<V2>>,
    etag_if_none_match: &EtagIfNoneMatch<'_>,
    model: Form<LoginModel<'_>>,
) -> Result<Redirect, TeraResponse> {
    let mut map = HashMap::new();

    map.insert("recaptcha_key", recaptcha.get_html_key_as_str().unwrap());

    let username = model.username.as_ref().ok();

    match username {
        Some(username) => {
            let password = model.password.as_ref().ok();

            match password {
                Some(password) => {
                    let recaptcha_token = model.recaptcha_token.as_ref().ok();

                    match recaptcha_token {
                        Some(recaptcha_token) => {
                            match recaptcha.verify(recaptcha_token, None).await {
                                Ok(_verification) => {
                                    // if _verification.score > 0.7 { // reCAPTCHA v2's score is always 1.0
                                    // Verify the username/password here
                                    if username.0 == "magiclen" && password.0 == "12345678" {
                                        map.insert(
                                            "message",
                                            "Login successfully, but not implement anything.",
                                        );
                                    } else {
                                        map.insert("message", "Invalid username or password.");
                                    }
                                    // } else {
                                    // map.insert("message", "You are probably not a human.");
                                    // }
                                }
                                Err(_) => {
                                    map.insert("message", "Please try again.");
                                }
                            }
                        }
                        None => {
                            map.insert("message", "Are you a human?");
                        }
                    }
                }
                None => {
                    map.insert("message", "The format of your password is incorrect.");
                }
            }
        }
        None => {
            map.insert("message", "The format of your username is incorrect.");
        }
    }

    Err(tera_response!(cm, etag_if_none_match, "login_v2", &map))
}

#[get("/")]
fn index() -> Redirect {
    Redirect::temporary(uri!(login_get))
}

#[launch]
async fn rocket() -> _ {
    rocket::build()
        .attach(tera_resources_initializer!(
            "login" => "examples/views/login.tera",
            "login_v2" => "examples/views/login_v2.tera"
        ))
        .attach(ReCaptcha::fairing())
        .attach(ReCaptcha::fairing_v2())
        .mount("/", routes![index])
        .mount("/", routes![login_get, login_post])
        .mount("/", routes![login_v2_get, login_v2_post])
}
