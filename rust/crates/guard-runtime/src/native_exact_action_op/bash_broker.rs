//! Exact compiled-image invocations requested by the frozen Bash child.

use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use guard_contained_process::{Isolation, PinnedCommand, ResourceLimits};

const HELPER_OUTPUT_CAP: usize = 256 * 1024;

pub(super) fn pair() -> io::Result<(std::fs::File, UnixStream)> {
    let (child, owner) = UnixStream::pair()?;
    let child = std::fs::File::from(OwnedFd::from(child));
    Ok((child, owner))
}

pub(super) fn serve(
    stream: UnixStream,
    expected: Vec<u16>,
    commands: Vec<PinnedCommand>,
    deadline: Instant,
    cancel: &AtomicBool,
) -> io::Result<()> {
    if expected.len() != commands.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compiled-image broker plan mismatch",
        ));
    }
    stream.set_read_timeout(Some(Duration::from_millis(25)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    for (id, command) in expected.into_iter().zip(commands) {
        let request = read_request(&mut reader, deadline, cancel)?;
        if request != id.to_string() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "compiled-image broker sequence mismatch",
            ));
        }
        let profile = profile(&command)?;
        let output = command.capture_hardened_image(
            b"",
            HELPER_OUTPUT_CAP,
            deadline,
            cancel,
            Isolation {
                seatbelt: Some(profile),
                resources: Some(ResourceLimits {
                    cpu_seconds: 2,
                    memory_bytes: libc::RLIM_INFINITY,
                    file_bytes: libc::RLIM_INFINITY,
                    open_files: libc::RLIM_INFINITY,
                    processes: 16,
                }),
                ..Isolation::default()
            },
        )?;
        let status = output.exit_code.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "compiled-image broker launch incomplete",
            )
        })?;
        let status = if status < 0 {
            128i32.saturating_add(status.saturating_abs()).min(255)
        } else {
            status.min(255)
        };
        writeln!(writer, "{status}")?;
        writeln!(writer, "{}", octal(&output.stdout))?;
        writeln!(writer, "{}", octal(&output.stderr))?;
        writer.flush()?;
    }
    Ok(())
}

fn read_request(
    reader: &mut BufReader<UnixStream>,
    deadline: Instant,
    cancel: &AtomicBool,
) -> io::Result<String> {
    let mut request = String::new();
    loop {
        if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match reader.read_line(&mut request) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(_) if request.ends_with('\n') => {
                request.pop();
                if request.len() > 5 || !request.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                return Ok(request);
            }
            Ok(_) if request.len() <= 6 => {}
            Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
    }
}

fn octal(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(4));
    for byte in bytes {
        write!(encoded, "\\{byte:03o}").expect("writing to String cannot fail");
    }
    encoded
}

fn profile(command: &PinnedCommand) -> io::Result<String> {
    // An opaque image cannot borrow modeled network authority from a sibling
    // curl invocation. The deny-default profile intentionally has no network
    // rule until compiled helpers have their own effect proof.
    let literal = |path: &std::path::Path| {
        serde_json::to_string(path.to_str().ok_or(io::ErrorKind::InvalidData)?)
            .map_err(io::Error::other)
    };
    let image = literal(command.effective_executable_path())?;
    let cwd = literal(command.cwd())?;
    Ok(format!(
        r#"(version 1)
(deny default)
(import "system.sb")
(allow process-fork)
(allow process-exec (literal {image}))
(allow file-read* (subpath "/System") (subpath "/usr/lib") (subpath "/dev") (literal {image}))
(allow file-read-metadata)
(allow file-read-data (literal {cwd}))
(allow file-map-executable (subpath "/System") (subpath "/usr/lib") (literal {image}))
(allow file-write* (literal "/dev/null"))
(allow sysctl-read)
(allow signal)"#
    ))
}
