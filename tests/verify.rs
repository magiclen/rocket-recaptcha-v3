use std::net::{IpAddr, SocketAddr};

use rocket::tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use rocket_recaptcha_v3::{
    ReCaptcha, ReCaptchaErrorCode, ReCaptchaToken, V3,
    chrono::prelude::*,
    rocket_client_addr::{ClientIpConfig, HeaderMap},
    validators::prelude::*,
};

const HTML_KEY: &str = "6Lf6dLIUAAAAAAxghN7nH6m_yuLfHwdD3N7FpanR";
const SECRET_KEY: &str = "6Lf6dLIUAAAAAHdJ4e0nsv-8OpFH-7Oad1XQ95rq";
const TOKEN: &str = "03AGdBq26ZLoBGGe_2NrTb7pOEJ7Zvz9bWmNfMxhAeIzE-VeQyRcM";

const SUCCESS_ANSWER: &str = r#"{"success":true,"score":0.9,"action":"login","challenge_ts":"2026-08-02T09:30:00Z","hostname":"magiclen.org"}"#;
const FAILURE_ANSWER: &str = r#"{"success":false,"error-codes":["timeout-or-duplicate"]}"#;

/// Serve one canned `siteverify` answer, and hand the request that asked for it back to the test.
fn spawn_siteverify_mock(answer: &'static str) -> (SocketAddr, JoinHandle<String>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();

    listener.set_nonblocking(true).unwrap();

    let address = listener.local_addr().unwrap();
    let listener = TcpListener::from_std(listener).unwrap();

    let handle = rocket::tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let request = read_request(&mut stream).await;

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            answer.len(),
            answer
        );

        stream.write_all(response.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        request
    });

    (address, handle)
}

/// Read one whole request, which has arrived once its body is as long as its `Content-Length` announced.
async fn read_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0u8; 512];

    loop {
        let read = stream.read(&mut buffer).await.unwrap();

        if read == 0 {
            break;
        }

        request.extend_from_slice(&buffer[..read]);

        if let Some(length) = request_length(&request)
            && request.len() >= length
        {
            break;
        }
    }

    String::from_utf8(request).unwrap()
}

/// Return how long a request is in total, once enough of it has arrived to tell.
fn request_length(request: &[u8]) -> Option<usize> {
    let (headers, _) = str::from_utf8(request).ok()?.split_once("\r\n\r\n")?;

    let body_length = headers
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|line| line.split_once(':'))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);

    Some(headers.len() + 4 + body_length)
}

fn recaptcha_for(address: SocketAddr) -> ReCaptcha<V3> {
    let mut recaptcha = ReCaptcha::<V3>::parse_str(Some(HTML_KEY), SECRET_KEY).unwrap();

    recaptcha.set_api_url(format!("http://{address}/recaptcha/api/siteverify"));

    recaptcha
}

#[test]
fn verify_a_genuine_token() {
    rocket::async_test(async {
        let (address, handle) = spawn_siteverify_mock(SUCCESS_ANSWER);

        let recaptcha = recaptcha_for(address);
        let token = ReCaptchaToken::parse_str(TOKEN).unwrap();

        let verification = recaptcha.verify(&token, None).await.unwrap();

        assert_eq!(0.9, verification.score);
        assert_eq!(Some(String::from("login")), verification.action);
        assert_eq!("magiclen.org", verification.hostname);
        assert_eq!(
            "2026-08-02T09:30:00Z".parse::<DateTime<Utc>>().unwrap(),
            verification.challenge_ts
        );

        let request = handle.await.unwrap();
        let (headers, body) = request.split_once("\r\n\r\n").unwrap();

        // The secret key has to travel in the body, so that it never reaches a URL.
        assert!(headers.starts_with("POST /recaptcha/api/siteverify HTTP/1.1"));
        assert_eq!(format!("secret={SECRET_KEY}&response={TOKEN}"), body);
    });
}

#[test]
fn report_the_client_ip_to_the_siteverify_api() {
    rocket::async_test(async {
        let (address, handle) = spawn_siteverify_mock(SUCCESS_ANSWER);

        let recaptcha = recaptcha_for(address);
        let token = ReCaptchaToken::parse_str(TOKEN).unwrap();

        let client_ip_config = ClientIpConfig::builder().trust_no_proxy();
        let client_ip = client_ip_config
            .resolve_client_ip(&HeaderMap::new(), "203.0.113.10".parse::<IpAddr>().unwrap());

        recaptcha.verify(&token, Some(&client_ip)).await.unwrap();

        let request = handle.await.unwrap();
        let (_, body) = request.split_once("\r\n\r\n").unwrap();

        assert_eq!(format!("secret={SECRET_KEY}&response={TOKEN}&remoteip=203.0.113.10"), body);
    });
}

#[test]
fn report_the_error_codes_of_a_rejected_token() {
    rocket::async_test(async {
        let (address, handle) = spawn_siteverify_mock(FAILURE_ANSWER);

        let recaptcha = recaptcha_for(address);
        let token = ReCaptchaToken::parse_str(TOKEN).unwrap();

        let error = recaptcha.verify(&token, None).await.unwrap_err();

        assert_eq!([ReCaptchaErrorCode::TimeoutOrDuplicate].as_slice(), error.error_codes());

        handle.await.unwrap();
    });
}
