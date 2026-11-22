//! Exercise the real CLI, SDK endpoint routing and SigV4 signing against local HTTP.
//! No cloud credentials or external S3 service are required.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

fn run_check(status: &str) -> (std::process::Output, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let status = status.to_owned();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "SDK did not connect");
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.ends_with(b"\r\n\r\n") {
            let count = stream.read(&mut buffer).unwrap();
            assert!(count > 0, "request ended before headers");
            request.extend_from_slice(&buffer[..count]);
            assert!(request.len() < 65536);
        }
        write!(stream, "HTTP/1.1 {status}\r\nContent-Length: 0\r\nx-amz-bucket-region: us-east-1\r\nConnection: close\r\n\r\n").unwrap();
        String::from_utf8(request).unwrap()
    });
    let output = Command::new(env!("CARGO_BIN_EXE_eedfs"))
        .args([
            "s3",
            "check",
            "--bucket",
            "eedfs-test",
            "--region",
            "us-east-1",
            "--endpoint-url",
            &endpoint,
            "--force-path-style",
            "--timeout-seconds",
            "5",
        ])
        .env("S3_ACCESS_KEY_ID", "eedfs-test-key")
        .env("S3_SECRET_ACCESS_KEY", "eedfs-test-secret")
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .env_remove("AWS_PROFILE")
        .env_remove("AWS_SESSION_TOKEN")
        .env_remove("S3_SESSION_TOKEN")
        .env("AWS_CONFIG_FILE", "/dev/null")
        .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
        .env("RUST_LOG", "off")
        .output()
        .unwrap();
    (output, server.join().unwrap())
}

#[test]
fn bucket_check_sends_signed_head_without_writing() {
    let (output, request) = run_check("200 OK");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        request.starts_with("HEAD /eedfs-test/ HTTP/1.1\r\n"),
        "{request}"
    );
    let headers = request.to_ascii_lowercase();
    assert!(headers.contains("authorization: aws4-hmac-sha256 "));
    assert!(headers.contains("credential=eedfs-test-key/"));
    assert!(headers.contains("/us-east-1/s3/aws4_request"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("S3 bucket access verified"));
}

#[test]
fn bucket_access_denied_is_a_failure() {
    let (output, _) = run_check("403 Forbidden");
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("access verified"));
}

#[test]
fn partial_credentials_are_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_eedfs"))
        .args(["s3", "check", "--bucket", "eedfs-test", "--region", "auto"])
        .env("S3_ACCESS_KEY_ID", "incomplete-test-key")
        .env_remove("S3_SECRET_ACCESS_KEY")
        .env_remove("S3_SESSION_TOKEN")
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .env("RUST_LOG", "off")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("set both S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY"));
    assert!(!error.contains("incomplete-test-key"));
}

#[test]
fn aws_credentials_are_not_used_as_a_fallback() {
    let output = Command::new(env!("CARGO_BIN_EXE_eedfs"))
        .args(["s3", "check", "--bucket", "eedfs-test"])
        .env_remove("S3_ACCESS_KEY_ID")
        .env_remove("S3_SECRET_ACCESS_KEY")
        .env_remove("S3_SESSION_TOKEN")
        .env("AWS_ACCESS_KEY_ID", "unused-aws-key")
        .env("AWS_SECRET_ACCESS_KEY", "unused-aws-secret")
        .env("RUST_LOG", "off")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("set both S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY"));
    assert!(!error.contains("unused-aws-secret"));
}
