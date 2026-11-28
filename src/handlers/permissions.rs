//! Local numeric credentials only; no cross-client identity/account lookup.
use cocryptfs::volume::Error;
use fuser::Request;
pub(super) fn actor(req: &Request, gid: Option<u32>) -> Result<(u32, u32), Error> {
    let uid = req.uid().ok_or(Error::Permission)?;
    let primary = req.gid().ok_or(Error::Permission)?;
    let Some(wanted) = gid.filter(|g| *g != primary) else {
        return Ok((uid, primary));
    };
    if uid == 0 {
        return Ok((uid, primary));
    }
    // Request IDs/PID come from the local kernel. Check the fsuid before using
    // supplementary numeric groups, rather than consulting usernames or peers.
    let status = std::fs::read_to_string(format!("/proc/{}/status", req.pid()))
        .map_err(|_| Error::Permission)?;
    let fsuid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|l| l.split_whitespace().nth(3))
        .and_then(|v| v.parse::<u32>().ok());
    if fsuid != Some(uid) {
        return Err(Error::Permission);
    }
    let member = status
        .lines()
        .find_map(|l| l.strip_prefix("Groups:"))
        .is_some_and(|l| l.split_whitespace().any(|v| v.parse::<u32>() == Ok(wanted)));
    Ok((uid, if member { wanted } else { primary }))
}
