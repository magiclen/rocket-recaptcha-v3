#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket_include_tera;

#[macro_use]
extern crate validators;

#[macro_use]
extern crate lazy_static;

extern crate regex;

#[macro_use]
extern crate rocket;

extern crate rocket_recaptcha_v3;

use std::collections::HashMap;

use validators::ValidatedCustomizedStringError;

use regex::Regex;

use rocket::State;
use rocket::request::Form;
use rocket::response::Redirect;

use rocket_include_tera::{TeraResponse, TeraContextManager};
use rocket_recaptcha_v3::{ReCaptcha, ReCaptchaToken};

lazy_static! {
    static ref RE_USERNAME: Regex = {
        Regex::new(r"^\w{1,30}$").unwrap()
    };

    static ref RE_PASSWORD: Regex = {
        Regex::new(r"^[\S ]{8,}$").unwrap()
    };
}

validated_customized_regex_string!(Username, ref RE_USERNAME);
validated_customized_regex_string!(Password, ref RE_PASSWORD);

const RECAPTCHA_HTML_KEY: &str = "6Lf6dLIUAAAAAAxghN7nH6m_yuLfHwdD3N7FpanR";
const RECAPTCHA_SECRET_KEY: &str = "6Lf6dLIUAAAAAHdJ4e0nsv-8OpFH-7Oad1XQ95rq";

#[derive(Debug, FromForm)]
struct LoginModel {
    username: Result<Username, ValidatedCustomizedStringError>,
    password: Result<Password, ValidatedCustomizedStringError>,
    recaptcha_token: Result<ReCaptchaToken, ValidatedCustomizedStringError>,
}

#[get("/login")]
fn login_get(cm: State<TeraContextManager>, recaptcha: State<ReCaptcha>) -> TeraResponse {
    tera_response_cache!(
        cm,
        "login",
        {
            println!("Generate login and cache it...");

            let mut map = HashMap::new();

            map.insert("recaptcha_key", recaptcha.get_html_key_as_str().unwrap());

            tera_response!("login", &map)
        }
    )
}

#[post("/login", data = "<model>")]
fn login_post(recaptcha: State<ReCaptcha>, model: Form<LoginModel>) -> Result<Redirect, TeraResponse> {
    let mut map = HashMap::new();

    map.insert("recaptcha_key", recaptcha.get_html_key_as_str().unwrap());

    match model.username.as_ref() {
        Ok(_username) => {
            match model.password.as_ref() {
                Ok(_password) => {
                    match model.recaptcha_token.as_ref() {
                        Ok(recaptcha_token) => {
                            match recaptcha.verify(recaptcha_token, None) {
                                Ok(verification) => {
                                    if verification.score > 0.7 {
                                        // Verify the username/password here

                                        map.insert("message", "Invalid username or password.");
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
                            map.insert("message", "The format of your reCAPTCHA token is incorrect.");
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

#[get("/")]
fn index() -> Redirect {
    Redirect::temporary(uri!(login_get))
}

fn main() {
    rocket::ignite()
        .attach(TeraResponse::fairing(|tera| {
            tera_resources_initialize!(
                tera,
                "login", "examples/views/login.tera",
            );
        }))
        .manage(ReCaptcha::from_str(Some(RECAPTCHA_HTML_KEY), RECAPTCHA_SECRET_KEY).unwrap())
        .mount("/", routes![index])
        .mount("/", routes![login_get, login_post])
        .launch();
}