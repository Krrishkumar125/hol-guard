//! The caller's authorization fence for a framed frozen-source launch.

use std::io;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use crate::{CapturedOutput, Isolation, PinnedCommand};

#[path = "source_ack.rs"]
mod acknowledgement;

pub(crate) struct SourceGate<'a> {
    pub gate: &'a mut dyn SourceLaunchGate,
    pub frame_before_commit: bool,
}

pub trait SourceLaunchGate {
    /// Revalidate current authority and atomically claim the grant. Keep any
    /// launch fence held until `released` or this capture returns an error.
    fn commit(&mut self) -> io::Result<()>;

    /// The kernel accepted the one-byte release marker. Record this local
    /// state before a fallible acknowledgement: an error after this point may
    /// have executed user code and must never trigger an automatic retry.
    /// This acknowledges dispatch, not user-code completion.
    fn released(&mut self) -> io::Result<()>;
}

impl PinnedCommand {
    /// A macOS system image is adopted only from the verified read-only root.
    /// Read-only modes on a private copied image do not establish this proof.
    #[cfg(target_os = "macos")]
    pub fn has_readonly_system_image(&self) -> io::Result<bool> {
        self.verify_bindings()?;
        self.image.on_readonly_system_root()
    }

    /// Feed source to a trusted framing bootstrap, then release its NUL marker
    /// only after `gate` commits. The caller must bind the interpreter/bootstrap
    /// and exact expected source length; arbitrary executables need not wait
    /// for this marker and cannot use this method as an authorization boundary.
    pub fn capture_frozen_source(
        self,
        source: &[u8],
        cap: usize,
        deadline: Instant,
        cancel: &AtomicBool,
        isolation: Isolation,
        gate: &mut dyn SourceLaunchGate,
    ) -> io::Result<CapturedOutput> {
        if cap == 0 || source.len() > 4 * 1024 * 1024 || source.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid frozen source frame",
            ));
        }
        crate::unix::capture(
            self,
            source,
            cap,
            deadline,
            cancel,
            isolation,
            Some(SourceGate {
                gate,
                frame_before_commit: false,
            }),
        )
    }

    /// Deliver a complete NUL-terminated source frame before committing, then
    /// release a second empty frame after authorization. The trusted bootstrap
    /// must send readiness `R` and dispatch `S` to reserved fd6. The process
    /// owner waits for each acknowledgment within the deadline before calling
    /// the corresponding gate callback. Other inherited files start at fd7.
    pub fn capture_acknowledged_source(
        self,
        source: &[u8],
        cap: usize,
        deadline: Instant,
        cancel: &AtomicBool,
        mut isolation: Isolation,
        gate: &mut dyn SourceLaunchGate,
    ) -> io::Result<CapturedOutput> {
        if cap == 0 || source.len() > 4 * 1024 * 1024 || source.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid frozen source frame",
            ));
        }
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;
        let (channel, writer) = UnixStream::pair()?;
        channel.set_nonblocking(true)?;
        isolation
            .inherited_files
            .insert(0, std::fs::File::from(OwnedFd::from(writer)));
        let mut acknowledged = acknowledgement::Gate {
            authority: gate,
            channel,
            deadline,
            cancel,
        };
        crate::unix::capture(
            self,
            source,
            cap,
            deadline,
            cancel,
            isolation,
            Some(SourceGate {
                gate: &mut acknowledged,
                frame_before_commit: true,
            }),
        )
    }
}

#[cfg(test)]
#[path = "source_launch_tests.rs"]
mod tests;
