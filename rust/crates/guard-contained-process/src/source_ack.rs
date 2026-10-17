//! A native-owned readiness/dispatch channel, separate from user output.

use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::SourceLaunchGate;

pub(super) struct Gate<'a> {
    pub authority: &'a mut dyn SourceLaunchGate,
    pub channel: UnixStream,
    pub deadline: Instant,
    pub cancel: &'a AtomicBool,
}

impl Gate<'_> {
    fn receive(&mut self, expected: u8) -> io::Result<()> {
        loop {
            if self.cancel.load(Ordering::Acquire) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .ok_or(io::ErrorKind::TimedOut)?;
            let mut poll = libc::pollfd {
                fd: self.channel.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // Poll returns immediately on readiness. Bound only the cancellation
            // observation interval; the caller's deadline remains authoritative.
            let milliseconds = remaining.as_millis().clamp(1, 10) as i32;
            let result = unsafe { libc::poll(&mut poll, 1, milliseconds) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if result == 0 {
                continue;
            }
            let mut byte = [0];
            match self.channel.read(&mut byte) {
                Ok(1) if byte[0] == expected => return Ok(()),
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
    }
}

impl SourceLaunchGate for Gate<'_> {
    fn commit(&mut self) -> io::Result<()> {
        self.receive(b'R')?;
        self.authority.commit()
    }

    fn released(&mut self) -> io::Result<()> {
        self.receive(b'S')?;
        self.authority.released()
    }
}
