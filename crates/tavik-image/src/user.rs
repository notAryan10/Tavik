use crate::error::ImageError;
use crate::filesystem::SafeDir;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Resolved user and group identity derived from image rootfs account databases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedUser {
    /// Numeric User ID.
    pub uid: u32,
    /// Primary Numeric Group ID.
    pub gid: u32,
    /// Supplementary Numeric Group IDs (excluding primary GID, deduplicated, sorted).
    pub additional_gids: Vec<u32>,
    /// Optional username if resolved from /etc/passwd or supplied as a named user.
    pub username: Option<String>,
    /// Optional primary group name if resolved from /etc/group.
    pub groupname: Option<String>,
}

#[derive(Debug, Clone)]
struct PasswdRecord {
    username: String,
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone)]
struct GroupRecord {
    groupname: String,
    gid: u32,
    members: Vec<String>,
}

/// Resolves user and group identity from an image rootfs and user string.
///
/// Supported User forms:
/// - `root`
/// - `username`
/// - `numeric UID`
/// - `username:groupname`
/// - `username:GID`
/// - `UID:groupname`
/// - `UID:GID`
///
/// Resolution Rules:
/// 1. No specified user defaults to UID 0 and GID 0.
/// 2. Named usernames must resolve in the image's `/etc/passwd`.
/// 3. Numeric UIDs are accepted even if no `/etc/passwd` record exists.
/// 4. When only a username or UID is supplied, the primary GID is taken from the matching `/etc/passwd` record.
/// 5. When a numeric UID has no `/etc/passwd` record, its GID defaults to 0.
/// 6. When an explicit group is supplied, it is resolved by name or numeric GID.
/// 7. Unknown named users or groups return clear errors.
/// 8. Rejects malformed strings, empty components, extra colons, null bytes, and numeric overflow.
/// 9. Supplementary groups are read from image `/etc/group`, excluding primary GID and deduplicated.
/// 10. Never consults host account databases (`/etc/passwd`, `/etc/group`, `getpwnam`, or `getgrnam`).
pub fn resolve_user(rootfs: &Path, user: Option<&str>) -> Result<ResolvedUser, ImageError> {
    let safe_dir = SafeDir::open_rootfs(rootfs)?;
    let passwd_content =
        safe_dir.read_file_to_string_limited(Path::new("etc/passwd"), 5 * 1024 * 1024)?;
    let group_content =
        safe_dir.read_file_to_string_limited(Path::new("etc/group"), 5 * 1024 * 1024)?;

    let passwd_records = passwd_content.as_deref().map(parse_passwd).transpose()?;
    let group_records = group_content.as_deref().map(parse_group).transpose()?;

    // Rule 1: No specified user defaults to UID 0 and GID 0
    let Some(user_raw) = user else {
        return Ok(ResolvedUser {
            uid: 0,
            gid: 0,
            additional_gids: Vec::new(),
            username: None,
            groupname: None,
        });
    };

    if user_raw.is_empty() {
        return Err(ImageError::InvalidConfiguration(
            "User specification must not be empty".to_string(),
        ));
    }

    if user_raw.contains('\0') {
        return Err(ImageError::InvalidConfiguration(
            "User specification contains forbidden null byte".to_string(),
        ));
    }

    let parts: Vec<&str> = user_raw.split(':').collect();
    if parts.len() > 2 {
        return Err(ImageError::InvalidConfiguration(format!(
            "Extra colon separator in user specification '{user_raw}': expected 'user' or 'user:group'"
        )));
    }

    let (user_part, group_part) = match parts.as_slice() {
        [u] => (*u, None),
        [u, g] => (*u, Some(*g)),
        _ => unreachable!(),
    };

    if user_part.is_empty() {
        return Err(ImageError::InvalidConfiguration(format!(
            "Empty user component in user specification '{user_raw}'"
        )));
    }

    if let Some(g) = group_part {
        if g.is_empty() {
            return Err(ImageError::InvalidConfiguration(format!(
                "Empty group component in user specification '{user_raw}'"
            )));
        }
    }

    // Resolve User Part
    let (uid, resolved_username, passwd_gid) = match parse_numeric_id(user_part)? {
        Some(numeric_uid) => {
            // Rule 3: Numeric UIDs are accepted even if no passwd entry exists.
            // Rule 4: When numeric UID has a matching passwd record, use its primary GID.
            if let Some(records) = &passwd_records {
                if let Some(rec) = records.iter().find(|r| r.uid == numeric_uid) {
                    (numeric_uid, Some(rec.username.clone()), Some(rec.gid))
                } else {
                    (numeric_uid, None, None)
                }
            } else {
                (numeric_uid, None, None)
            }
        }
        None => {
            // Rule 2: A username must resolve in the image's passwd database.
            let records = passwd_records.as_ref().ok_or_else(|| {
                ImageError::InvalidConfiguration(format!(
                    "Cannot resolve named user '{user_part}': /etc/passwd file not found in image rootfs"
                ))
            })?;
            let rec = records
                .iter()
                .find(|r| r.username == user_part)
                .ok_or_else(|| {
                    ImageError::InvalidConfiguration(format!(
                    "Unknown named user '{user_part}': user does not exist in image /etc/passwd"
                ))
                })?;
            (rec.uid, Some(rec.username.clone()), Some(rec.gid))
        }
    };

    // Resolve Group Part
    let (gid, resolved_groupname) = if let Some(grp) = group_part {
        match parse_numeric_id(grp)? {
            Some(numeric_gid) => {
                let gname = group_records
                    .as_ref()
                    .and_then(|recs| recs.iter().find(|r| r.gid == numeric_gid))
                    .map(|r| r.groupname.clone());
                (numeric_gid, gname)
            }
            None => {
                let records = group_records.as_ref().ok_or_else(|| {
                    ImageError::InvalidConfiguration(format!(
                        "Cannot resolve named group '{grp}': /etc/group file not found in image rootfs"
                    ))
                })?;
                let rec = records.iter().find(|r| r.groupname == grp).ok_or_else(|| {
                    ImageError::InvalidConfiguration(format!(
                        "Unknown named group '{grp}': group does not exist in image /etc/group"
                    ))
                })?;
                (rec.gid, Some(rec.groupname.clone()))
            }
        }
    } else {
        // Rule 4: When only username or UID is supplied, use primary GID from matching passwd record.
        // Rule 5: When the numeric UID has no passwd entry, default its GID to 0.
        let effective_gid = passwd_gid.unwrap_or(0);
        let gname = group_records
            .as_ref()
            .and_then(|recs| recs.iter().find(|r| r.gid == effective_gid))
            .map(|r| r.groupname.clone());
        (effective_gid, gname)
    };

    // Resolve Supplementary Groups
    let mut additional_gids = Vec::new();
    if let Some(ref uname) = resolved_username {
        if let Some(records) = &group_records {
            for rec in records {
                if rec.members.iter().any(|m| m == uname) && rec.gid != gid {
                    additional_gids.push(rec.gid);
                }
            }
        }
    }

    additional_gids.sort_unstable();
    additional_gids.dedup();

    Ok(ResolvedUser {
        uid,
        gid,
        additional_gids,
        username: resolved_username,
        groupname: resolved_groupname,
    })
}

fn parse_numeric_id(s: &str) -> Result<Option<u32>, ImageError> {
    if s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty() {
        let val = s.parse::<u32>().map_err(|e| {
            ImageError::InvalidConfiguration(format!(
                "Numeric ID '{s}' exceeds maximum allowed value (u32::MAX): {e}"
            ))
        })?;
        Ok(Some(val))
    } else {
        Ok(None)
    }
}

fn parse_passwd(content: &str) -> Result<Vec<PasswdRecord>, ImageError> {
    let mut records = Vec::new();
    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 4 {
            return Err(ImageError::InvalidConfiguration(format!(
                "Malformed /etc/passwd record at line {}: expected at least 4 fields, found {}",
                line_num + 1,
                fields.len()
            )));
        }
        let username = fields[0];
        if username.is_empty() {
            return Err(ImageError::InvalidConfiguration(format!(
                "Malformed /etc/passwd record at line {}: username is empty",
                line_num + 1
            )));
        }
        let uid = fields[2].parse::<u32>().map_err(|e| {
            ImageError::InvalidConfiguration(format!(
                "Malformed /etc/passwd record at line {}: invalid numeric UID '{}': {e}",
                line_num + 1,
                fields[2]
            ))
        })?;
        let gid = fields[3].parse::<u32>().map_err(|e| {
            ImageError::InvalidConfiguration(format!(
                "Malformed /etc/passwd record at line {}: invalid numeric GID '{}': {e}",
                line_num + 1,
                fields[3]
            ))
        })?;
        records.push(PasswdRecord {
            username: username.to_string(),
            uid,
            gid,
        });
    }
    Ok(records)
}

fn parse_group(content: &str) -> Result<Vec<GroupRecord>, ImageError> {
    let mut records = Vec::new();
    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 3 {
            return Err(ImageError::InvalidConfiguration(format!(
                "Malformed /etc/group record at line {}: expected at least 3 fields, found {}",
                line_num + 1,
                fields.len()
            )));
        }
        let groupname = fields[0];
        if groupname.is_empty() {
            return Err(ImageError::InvalidConfiguration(format!(
                "Malformed /etc/group record at line {}: groupname is empty",
                line_num + 1
            )));
        }
        let gid = fields[2].parse::<u32>().map_err(|e| {
            ImageError::InvalidConfiguration(format!(
                "Malformed /etc/group record at line {}: invalid numeric GID '{}': {e}",
                line_num + 1,
                fields[2]
            ))
        })?;
        let members: Vec<String> = if fields.len() >= 4 && !fields[3].trim().is_empty() {
            fields[3]
                .split(',')
                .map(|m| m.trim().to_string())
                .filter(|m| !m.is_empty())
                .collect()
        } else {
            Vec::new()
        };
        records.push(GroupRecord {
            groupname: groupname.to_string(),
            gid,
            members,
        });
    }
    Ok(records)
}
