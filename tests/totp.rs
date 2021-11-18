use otp_rs::TOTP;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_generate() {
  let timestamp = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();
  let otp = TOTP::new("secret");
  let code = otp.generate(4, timestamp);

  assert!(code.unwrap().to_string().len() <= 6);
}

#[test]
fn test_verify() {
  let otp = TOTP::new("python");
  let timestamp1 = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();
  let code = otp
    .generate(30, timestamp1)
    .expect("Failed to generate code");
  let timestamp2 = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();

  assert!(otp.verify(code, 30, timestamp2));
  assert!(!otp.verify(123456, 30, timestamp2));
  assert!(!otp.verify(1234567, 30, timestamp2));
}

#[test]
fn test_to_uri() {
  let otp = TOTP::new("secret");
  let expect = "otpauth://totp/secret?secret=ONSWG4TFOQ&issuer=secret";

  assert_eq!(expect, otp.to_uri("secret", "secret"));
}
