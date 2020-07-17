#![feature(proc_macro_hygiene, decl_macro)]

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

use rocket::request::Form;
use rocket::response::Redirect;
use rocket::State;

use rocket_include_tera::{TeraContextManager, TeraResponse};
use rocket_recaptcha_v3::{ReCaptcha, ReCaptchaToken, V2};

use validators::prelude::*;
use validators::{Base64UrlError, RegexError};
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
struct LoginModel {
    username: Result<Username, RegexError>,
    password: Result<Password, RegexError>,
    recaptcha_token: Result<ReCaptchaToken, Base64UrlError>,
}

#[get("/login")]
fn login_get(cm: State<TeraContextManager>, recaptcha: State<ReCaptcha>) -> TeraResponse {
    tera_response_cache!(cm, "login", {
        println!("Generate login and cache it...");

        let mut map = HashMap::new();

        map.insert("recaptcha_key", recaptcha.get_html_key_as_str().unwrap());

        tera_response!("login", &map)
    })
}

#[post("/login", data = "<model>")]
fn login_post(
    recaptcha: State<ReCaptcha>,
    model: Form<LoginModel>,
) -> Result<Redirect, TeraResponse> {
    let mut map = HashMap::new();

    map.insert("recaptcha_key", recaptcha.get_html_key_as_str().unwrap());

    match model.username.as_ref() {
        Ok(username) => {
            match model.password.as_ref() {
                Ok(password) => {
                    match model.recaptcha_token.as_ref() {
                        Ok(recaptcha_token) => {
                            match recaptcha.verify(recaptcha_token, None) {
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
                        Err(_) => {
                            map.insert(
                                "message",
                                "The format of your reCAPTCHA token is incorrect.",
                            );
                        }
                    }
                }
                Err(_) => {
                    map.insert("message", "The format of your password is incorrect.");
                }
            }
        }
        Err(_) => {
            map.insert("message", "The format of your username is incorrect.");
        }
    }

    Err(tera_response!("login", &map))
}

#[get("/login-v2")]
fn login_v2_get(cm: State<TeraContextManager>, recaptcha: State<ReCaptcha<V2>>) -> TeraResponse {
    tera_response_cache!(cm, "login_v2", {
        println!("Generate login-v2 and cache it...");

        let mut map = HashMap::new();

        map.insert("recaptcha_key", recaptcha.get_html_key_as_str().unwrap());

        tera_response!("login_v2", &map)
    })
}

#[post("/login-v2", data = "<model>")]
fn login_v2_post(
    recaptcha: State<ReCaptcha<V2>>,
    model: Form<LoginModel>,
) -> Result<Redirect, TeraResponse> {
    let mut map = HashMap::new();

    map.insert("recaptcha_key", recaptcha.get_html_key_as_str().unwrap());

    match model.username.as_ref() {
        Ok(username) => {
            match model.password.as_ref() {
                Ok(password) => {
                    match model.recaptcha_token.as_ref() {
                        Ok(recaptcha_token) => {
                            match recaptcha.verify(recaptcha_token, None) {
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
                        Err(_) => {
                            map.insert("message", "Are you a human?");
                        }
                    }
                }
                Err(_) => {
                    map.insert("message", "The format of your password is incorrect.");
                }
            }
        }
        Err(_) => {
            map.insert("message", "The format of your username is incorrect.");
        }
    }

    Err(tera_response!("login_v2", &map))
}

#[get("/")]
fn index() -> Redirect {
    Redirect::temporary(uri!(login_get))
}

fn main() {
    rocket::ignite()
        .attach(TeraResponse::fairing(|tera| {
            tera_resources_initialize!(
                tera,
                "login",
                "examples/views/login.tera",
                "login_v2",
                "examples/views/login_v2.tera"
            );
        }))
        .attach(ReCaptcha::fairing())
        .attach(ReCaptcha::fairing_v2())
        .mount("/", routes![index])
        .mount("/", routes![login_get, login_post])
        .mount("/", routes![login_v2_get, login_v2_post])
        .launch();
}
