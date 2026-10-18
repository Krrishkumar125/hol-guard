//! Read-only system image acquisition and applicable startup configuration.
use super::*;

impl Resolver<'_> {
    pub(super) fn image(&self, path: &Path) -> Result<PinnedCommand> {
        self.check()?;
        let pinned = PinnedCommand::new(path, &[], self.cwd, &[])
            .map_err(|_| "bash_system_image_unavailable")?;
        if !pinned
            .has_readonly_system_image()
            .map_err(|_| "bash_system_image_unavailable")?
        {
            return Err("bash_system_image_not_immutable");
        }
        self.check()?;
        Ok(pinned)
    }
}

pub(super) fn capture(resolver: &Resolver<'_>, path: &Path) -> Result<graph::Executable> {
    let pinned = resolver.image(path)?;
    let openssl_config = if path == Path::new("/usr/bin/curl") {
        super::super::super::bash_curl_backend::verify(&pinned, resolver.cwd, resolver.deadline)?;
        let config = "/private/etc/ssl/openssl.cnf";
        Some(resolver.code(config, &canonical(config)?)?)
    } else {
        None
    };
    Ok(graph::Executable::Native {
        resolved_path: text(path)?,
        content_sha256: pinned.executable_digest,
        openssl_config,
    })
}
