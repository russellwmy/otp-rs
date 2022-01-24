# otp-rs

RFC-complaint one-time password algorithms written in Rust.

The HMAC-based one-time password algorithm is implemented as per [RFC4226](http://tools.ietf.org/html/rfc4226). The time-based one-time password algorithm is implemented as per [RFC 6238](http://tools.ietf.org/html/rfc6238).

# Installation

```
[dependencies]
otp-rs= "0.1"
```

# HOTP Example

```
let otp = HOTP::new("secret");
/// Generate code with counter 0 input
let code = otp.generate(0).unwrap();

println!("{}", code);
```

# TOTP Example

```
let otp = TOTP::new("secret");
/// Generate code with period and current timestamp
let timestamp = SystemTime::now()
  .duration_since(UNIX_EPOCH)
  .unwrap()
  .as_secs();
let code = otp.generate(30, timestamp);
println!("{}", code);
```
