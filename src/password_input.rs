//! Explicit password files for automation, or hidden input on the controlling TTY.
use eedfs::storage::s3::ConnectionError;
use std::path::Path;
use zeroize::Zeroizing;

pub fn read(
    path: Option<&Path>,
    prompt: &str,
    confirm: bool,
) -> Result<Zeroizing<Vec<u8>>, ConnectionError> {
    if let Some(path) = path {
        let mut bytes = Zeroizing::new(std::fs::read(path)?);
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        if bytes.is_empty() {
            return Err("password file is empty".into());
        }
        return Ok(bytes);
    }
    // Do not consume redirected stdin or silently fall back to visible input.
    std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty")
        .map_err(|_| "no controlling terminal; supply --password-file (and --new-password-file when changing passwords)")?;
    let password = Zeroizing::new(rpassword::prompt_password(prompt)?);
    if password.is_empty() {
        return Err("password must not be empty".into());
    }
    if confirm {
        let confirmation = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
        if password.as_bytes() != confirmation.as_bytes() {
            return Err("passwords do not match".into());
        }
    }
    Ok(Zeroizing::new(password.as_bytes().to_vec()))
}
