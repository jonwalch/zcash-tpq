//! Bounded, strict UTF-8 password input. Configure the terminal before prompting.
use std::io;
use zeroize::Zeroizing;

#[cfg(unix)]
pub fn password(prompt: &str) -> io::Result<Zeroizing<String>> {
    use std::io::Write;

    let mut terminal = unix::PrivateTerminal::open()?;
    let result = (|| {
        terminal.file.write_all(prompt.as_bytes())?;
        terminal.file.flush()?;
        read_password(&mut terminal.file)
    })();
    // Restoration errors must prevent use of the password too. The drop guard
    // retries restoration if an explicit attempt fails, including during setup.
    terminal.restore()?;
    terminal.file.write_all(b"\n")?;
    result
}

#[cfg(not(unix))]
pub fn password(_prompt: &str) -> io::Result<Zeroizing<String>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private terminal input is supported only on Unix",
    ))
}

#[cfg(any(unix, test))]
fn read_password(input: &mut impl io::Read) -> io::Result<Zeroizing<String>> {
    const LIMIT: usize = 1024;
    // Never grow a secret buffer: reallocation could leave an uncleared copy.
    let mut bytes = Zeroizing::new(Vec::with_capacity(LIMIT));
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        if input.read(&mut *byte)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "password input ended before Enter",
            ));
        }
        match byte[0] {
            b'\r' | b'\n' => break,
            // Raw mode makes cancellation a recoverable error, allowing us to
            // restore the terminal instead of exiting on a keyboard signal.
            3 | 4 | 26 => {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "password input cancelled",
                ));
            }
            8 | 127 => {
                // Remove a complete UTF-8 character when valid; an invalid byte
                // can be explicitly erased, but never silently replaced.
                let end = std::str::from_utf8(&bytes)
                    .ok()
                    .and_then(|s| s.char_indices().next_back().map(|(index, _)| index))
                    .unwrap_or_else(|| bytes.len().saturating_sub(1));
                bytes.truncate(end);
            }
            value => {
                if bytes.len() == LIMIT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "password exceeds 1024 UTF-8 bytes",
                    ));
                }
                bytes.push(value);
            }
        }
    }
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "password must not be empty",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "password is not valid UTF-8"))?;
    Ok(Zeroizing::new(text.to_owned()))
}

#[cfg(unix)]
mod unix {
    use super::io;
    use rustix::termios::{self, LocalModes, OptionalActions, SpecialCodeIndex, Termios};
    use std::fs::{File, OpenOptions};

    pub(super) struct PrivateTerminal {
        pub(super) file: File,
        original: Termios,
        restored: bool,
    }

    impl PrivateTerminal {
        pub(super) fn open() -> io::Result<Self> {
            let file = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
            let original = termios::tcgetattr(&file)?;
            let terminal = Self {
                file,
                original,
                restored: false,
            };
            let mut private = terminal.original.clone();
            // Byte input avoids platform-dependent canonical line-buffer limits
            // and leaves UTF-8 validation to our bounded reader.
            private.make_raw();
            private
                .local_modes
                .remove(LocalModes::ECHO | LocalModes::ECHONL);
            private.special_codes[SpecialCodeIndex::VMIN] = 1;
            private.special_codes[SpecialCodeIndex::VTIME] = 0;
            set_mode(&terminal.file, &private)?;
            Ok(terminal)
        }

        pub(super) fn restore(&mut self) -> io::Result<()> {
            if !self.restored {
                set_mode(&self.file, &self.original)?;
                self.restored = true;
            }
            Ok(())
        }
    }

    impl Drop for PrivateTerminal {
        fn drop(&mut self) {
            let _ = self.restore();
        }
    }

    fn set_mode(file: &File, requested: &Termios) -> io::Result<()> {
        // Flush queued input so leftover password bytes cannot reach the next
        // prompt or the shell after errors, cancellation or overlong input.
        termios::tcsetattr(file, OptionalActions::Flush, requested)?;
        // POSIX permits tcsetattr to apply only part of a requested change.
        let actual = termios::tcgetattr(file)?;
        if actual.input_modes != requested.input_modes
            || actual.output_modes != requested.output_modes
            || actual.control_modes != requested.control_modes
            || actual.local_modes != requested.local_modes
            || actual.special_codes[SpecialCodeIndex::VMIN]
                != requested.special_codes[SpecialCodeIndex::VMIN]
            || actual.special_codes[SpecialCodeIndex::VTIME]
                != requested.special_codes[SpecialCodeIndex::VTIME]
        {
            return Err(io::Error::other(
                "terminal did not apply password input mode",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_utf8_whitespace_and_editing() {
        for text in [" \tpublic-é-🔑 \t", "e\u{301}", "é", "public-�"] {
            let line = format!("{text}\n");
            assert_eq!(&*read_password(&mut line.as_bytes()).unwrap(), text);
        }
        assert_eq!(
            &*read_password(&mut "public-é🔑\x7f\x08z\r".as_bytes()).unwrap(),
            "public-z"
        );
        assert_eq!(
            &*read_password(&mut &b"\x08public-\xff\x7fok\n"[..]).unwrap(),
            "public-ok"
        );
    }

    #[test]
    fn malformed_utf8_and_byte_bounds() {
        for invalid in [
            &b"public-\xff\n"[..],
            &b"public-\xc3\n"[..],
            &b"public-\xc0\xaf\n"[..],
            &b"public-\xed\xa0\x80\n"[..],
            &b"\n"[..],
        ] {
            assert_eq!(
                read_password(&mut &*invalid).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        for text in ["a".repeat(1024), "é".repeat(512)] {
            assert_eq!(
                &*read_password(&mut format!("{text}\n").as_bytes()).unwrap(),
                &text
            );
            assert_eq!(
                read_password(&mut format!("{text}x\n").as_bytes())
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn unfinished_cancelled_and_failed_input() {
        assert_eq!(
            read_password(&mut &b"public-password"[..])
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        for cancel in [3, 4, 26] {
            assert_eq!(
                read_password(&mut &[b'a', cancel, b'\n'][..])
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Interrupted
            );
        }
        struct Failed;
        impl io::Read for Failed {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "read failed"))
            }
        }
        assert_eq!(
            read_password(&mut Failed).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
