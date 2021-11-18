use otp_rs::HOTP;

#[test]
fn test_generate() {
  let otp = HOTP::new("secret");
  let code = otp.generate(4);

  assert!(code.unwrap().to_string().len() <= 6);
}

#[test]
fn test_verify() {
  let otp = HOTP::new("secret");
  let code = otp.generate(4).unwrap();

  assert!(otp.verify(code, 0, 100));
  assert!(!otp.verify(123456, 0, 100));
  assert!(!otp.verify(1234567, 0, 100));
}

#[test]
fn test_to_uri() {
  let otp = HOTP::new("secret");
  let expect = "otpauth://hotp/secret?secret=ONSWG4TFOQ&issuer=secret&counter=4";

  assert_eq!(expect, otp.to_uri("secret", "secret", 4));
}
