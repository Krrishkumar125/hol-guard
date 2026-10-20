//! Whether a directory belongs to the user the agent runs as.
//!
//! Classification routes that admit a directory outside the session workspace
//! ask this before they treat it as the agent's own checkout. On Unix the
//! question is the owning uid; here it is the owner SID in the directory's
//! security descriptor.

use std::path::Path;

use windows_permissions::constants::{SeObjectType, SecurityInformation};
use windows_permissions::utilities::current_process_sid;
use windows_permissions::wrappers::GetNamedSecurityInfo;

use super::private_files::trusted_private_owner;

/// Whether `path` carries an owner this user's own writes produce.
///
/// That is this process's SID, or SYSTEM or the Administrators group, which is
/// what Windows records when the creating token's default owner is the
/// Administrators group rather than the user. The same three are what the
/// runtime accepts as the owner of its own private files, for the same reason:
/// a stricter comparison rejects directories the agent itself created while
/// elevated. Ownership is the second screen here, not the first — a caller
/// asks only about a path it has already confined to the user's own profile.
///
/// The descriptor is read by name, the same way the Unix side reads the owning
/// uid of a path it has already resolved. A path whose descriptor cannot be
/// read, or that carries no owner at all, answers false rather than an error,
/// so a caller that cannot establish ownership keeps the review it would have
/// asked for anyway.
pub fn path_owned_by_current_user(path: &Path) -> bool {
    let Ok(current) = current_process_sid() else {
        return false;
    };
    let Ok(descriptor) = GetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner,
    ) else {
        return false;
    };
    descriptor
        .owner()
        .is_some_and(|owner| trusted_private_owner(owner, current.as_ref()))
}
