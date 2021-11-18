use anyhow::Result;
use data_encoding::BASE32_NOPAD;
use hmac::Hmac;
use hmac::Mac;
use hmac::NewMac;
use sha1::Sha1;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct HOTP {
  secret: Vec<u8>,
}

impl HOTP {
  pub fn new(secret: &str) -> HOTP {
    HOTP {
      secret: secret.as_bytes().to_vec(),
    }
  }

  pub fn from_base32(secret: &str) -> Result<HOTP> {
    let secret = BASE32_NOPAD
      .decode(secret.as_bytes())
      .expect("Invalid base32 value");
    Ok(HOTP { secret })
  }

  pub fn from_bytes(secret: &[u8]) -> HOTP {
    HOTP {
      secret: secret.to_vec(),
    }
  }

  pub fn generate(&self, counter: u64) -> Result<u32> {
    let mut hmac = Hmac::<Sha1>::new_from_slice(&self.secret).expect("Invalid secret");

    hmac.update(&counter.to_be_bytes());
    let result = hmac.finalize();
    let digest = result.into_bytes();
    let offset = (digest.last().expect("Invalid Digest") & 0xf) as usize;
    let code: [u8; 4] = digest[offset..offset + 4]
      .try_into()
      .expect("Invalid digest");
    let code = u32::from_be_bytes(code);
    Ok(code & 0x7fffffff % 1000000)
  }

  pub fn verify(&self, code: u32, last: u64, trials: u64) -> bool {
    let code_str = code.to_string();
    let code_bytes = code_str.as_bytes();
    if code_bytes.len() > 6 {
      return false;
    }
    for i in last + 1..last + trials + 1 {
      println!("{}", i);
      let valid_code = self.generate(i).expect("Fail to generate code").to_string();
      let valid_bytes = valid_code.as_bytes();
      if code_bytes.len() != valid_code.len() {
        continue;
      }
      let mut rv = 0;
      for (a, b) in code_bytes.iter().zip(valid_bytes.iter()) {
        rv |= a ^ b;
      }
      if rv == 0 {
        return true;
      }
    }
    false
  }

  pub fn base32_secret(&self) -> String {
    BASE32_NOPAD.encode(&self.secret)
  }
  pub fn to_uri(&self, label: &str, issuer: &str, counter: u64) -> String {
    format!(
      "otpauth://hotp/{}?secret={}&issuer={}&counter={}",
      label,
      self.base32_secret(),
      issuer,
      counter
    )
  }
}
