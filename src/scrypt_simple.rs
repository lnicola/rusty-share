use byteorder::{ByteOrder, LittleEndian};
use rand::rngs::OsRng;
use rand::RngCore;
use scrypt::{self, ScryptParams};
use std::error;
use std::fmt;
use std::io;
use subtle::ConstantTimeEq;

/// `scrypt()` error
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct InvalidOutputLen;

/// `ScryptParams` error
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct InvalidParams;

/// `scrypt_check` error
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CheckError {
    /// Password hash mismatch, e.g. due to the incorrect password.
    HashMismatch,
    /// Invalid format of the hash string.
    InvalidFormat,
}

impl fmt::Display for InvalidOutputLen {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid output buffer length")
    }
}

impl error::Error for InvalidOutputLen {
    fn description(&self) -> &str {
        "invalid output buffer length"
    }
}

impl fmt::Display for InvalidParams {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid scrypt parameters")
    }
}

impl error::Error for InvalidParams {
    fn description(&self) -> &str {
        "invalid scrypt parameters"
    }
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            CheckError::HashMismatch => "password hash mismatch",
            CheckError::InvalidFormat => "invalid `hashed_value` format",
        })
    }
}

impl error::Error for CheckError {
    fn description(&self) -> &str {
        match *self {
            CheckError::HashMismatch => "password hash mismatch",
            CheckError::InvalidFormat => "invalid `hashed_value` format",
        }
    }
}

pub fn scrypt_simple(password: &str, log_n: u8, r: u32, p: u32) -> io::Result<String> {
    let params = ScryptParams::new(log_n, r, p).expect("recommended scrypt params should work");

    let mut salt = [0u8; 16];
    OsRng.try_fill_bytes(&mut salt)?;

    // 256-bit derived key
    let mut dk = [0u8; 32];

    scrypt::scrypt(password.as_bytes(), &salt, &params, &mut dk)
        .expect("32 bytes always satisfy output length requirements");

    // usually 128 bytes is enough
    let mut result = String::with_capacity(128);
    result.push_str("$rscrypt$");
    if r < 256 && p < 256 {
        result.push_str("0$");
        let mut tmp = [0u8; 3];
        tmp[0] = log_n;
        tmp[1] = r as u8;
        tmp[2] = p as u8;
        result.push_str(&base64::encode(&tmp));
    } else {
        result.push_str("1$");
        let mut tmp = [0u8; 9];
        tmp[0] = log_n;
        LittleEndian::write_u32(&mut tmp[1..5], r);
        LittleEndian::write_u32(&mut tmp[5..9], p);
        result.push_str(&base64::encode(&tmp));
    }
    result.push('$');
    result.push_str(&base64::encode(&salt));
    result.push('$');
    result.push_str(&base64::encode(&dk));
    result.push('$');

    Ok(result)
}

pub fn scrypt_check(password: &str, hashed_value: &str) -> Result<(), CheckError> {
    let mut iter = hashed_value.split('$');

    // Check that there are no characters before the first "$"
    if iter.next() != Some("") {
        Err(CheckError::InvalidFormat)?;
    }

    // Check the name
    if iter.next() != Some("rscrypt") {
        Err(CheckError::InvalidFormat)?;
    }

    // Parse format - currenlty only version 0 (compact) and 1 (expanded) are
    // supported
    let fstr = iter.next().ok_or(CheckError::InvalidFormat)?;
    let pvec = iter
        .next()
        .ok_or(CheckError::InvalidFormat)
        .and_then(|s| base64::decode(s).map_err(|_| CheckError::InvalidFormat))?;
    let params = match fstr {
        "0" if pvec.len() == 3 => {
            let log_n = pvec[0];
            let r = pvec[1] as u32;
            let p = pvec[2] as u32;
            ScryptParams::new(log_n, r, p).map_err(|_| CheckError::InvalidFormat)
        }
        "1" if pvec.len() == 9 => {
            let log_n = pvec[0];
            let mut pval = [0u32; 2];
            LittleEndian::read_u32_into(&pvec[1..9], &mut pval);
            ScryptParams::new(log_n, pval[0], pval[1]).map_err(|_| CheckError::InvalidFormat)
        }
        _ => Err(CheckError::InvalidFormat),
    }?;

    // Salt
    let salt = iter
        .next()
        .ok_or(CheckError::InvalidFormat)
        .and_then(|s| base64::decode(s).map_err(|_| CheckError::InvalidFormat))?;

    // Hashed value
    let hash = iter
        .next()
        .ok_or(CheckError::InvalidFormat)
        .and_then(|s| base64::decode(s).map_err(|_| CheckError::InvalidFormat))?;

    // Make sure that the input ends with a "$"
    if iter.next() != Some("") {
        Err(CheckError::InvalidFormat)?;
    }

    // Make sure there is no trailing data after the final "$"
    if iter.next() != None {
        Err(CheckError::InvalidFormat)?;
    }

    let mut output = vec![0u8; hash.len()];
    scrypt::scrypt(password.as_bytes(), &salt, &params, &mut output)
        .map_err(|_| CheckError::InvalidFormat)?;

    // Be careful here - its important that the comparison be done using a fixed
    // time equality check. Otherwise an adversary that can measure how long
    // this step takes can learn about the hashed value which would allow them
    // to mount an offline brute force attack against the hashed password.
    if output.ct_eq(&hash).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(CheckError::HashMismatch)?
    }
}
