use crate::HOTP;
use anyhow::Result;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct TOTP {
  hotp: HOTP,
}

impl TOTP {
  pub fn new(secret: &str) -> TOTP {
    TOTP {
      hotp: HOTP::new(secret),
    }
  }

  pub fn from_base32(secret: &str) -> Result<TOTP> {
    HOTP::from_base32(secret).map(|hotp| TOTP { hotp })
  }

  pub fn from_bytes(secret: &[u8]) -> TOTP {
    TOTP {
      hotp: HOTP::from_bytes(secret),
    }
  }

  pub fn generate(&self, period: u64, timestamp: u64) -> Result<u32> {
    let counter = timestamp / period;

    self.hotp.generate(counter)
  }

  pub fn verify(&self, code: u32, period: u64, timestamp: u64) -> bool {
    let code_str = code.to_string();
    let code_bytes = code_str.as_bytes();
    if code_bytes.len() > 6 {
      return false;
    }
    let valid_code = self
      .generate(period, timestamp)
      .expect("Fail to generate code")
      .to_string();
    let valid_bytes = valid_code.as_bytes();
    if code_bytes.len() != valid_code.len() {
      return false;
    }
    let mut rv = 0;
    for (a, b) in code_bytes.iter().zip(valid_bytes.iter()) {
      rv |= a ^ b;
    }
    rv == 0
  }

  pub fn to_uri(&self, label: &str, issuer: &str) -> String {
    format!(
      "otpauth://totp/{}?secret={}&issuer={}",
      label,
      self.hotp.base32_secret(),
      issuer
    )
  }
}
