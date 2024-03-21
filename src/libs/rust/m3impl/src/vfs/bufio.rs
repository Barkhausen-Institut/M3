/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2021 Nils Asmussen, Barkhausen Institut
 *
 * This file is part of M3 (Microkernel-based SysteM for Heterogeneous Manycores).
 *
 * M3 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * M3 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License version 2 for more details.
 */

use core::cmp;
use core::fmt;

use crate::col::{String, Vec};
use crate::errors::Error;
use crate::io::{Read, Write};
use crate::vec;
use crate::vfs::{Seek, SeekMode};

/// A reader implementation with an internal buffer
pub struct BufReader<R: Read> {
    reader: R,
    buf: Vec<u8>,
    pos: usize,
    cap: usize,
}

impl<R: Read> BufReader<R> {
    /// Creates a new `BufReader` with the given reader
    pub fn new(reader: R) -> Self {
        Self::with_capacity(reader, 512)
    }

    /// Creates a new `BufReader` with the given reader, using a buffer with `cap` bytes
    pub fn with_capacity(reader: R, cap: usize) -> Self {
        Self {
            reader,
            buf: vec![0u8; cap],
            pos: 0,
            cap: 0,
        }
    }

    /// Returns a reference to the internal reader
    pub fn get_ref(&self) -> &R {
        &self.reader
    }

    /// Returns a mutable reference to the internal reader
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Reads a line from the reader, appends it to `s`, and returns the number of read bytes
    pub fn read_line(&mut self, s: &mut String) -> Result<usize, Error> {
        let mut total = 0;
        loop {
            let mut buf = [0u8; 1];
            let len = self.read(&mut buf)?;
            if len == 0 || buf[0] == b'\n' {
                break;
            }

            s.push(buf[0] as char);
            total += 1;
        }
        Ok(total)
    }
}

impl<R: Read> Read for BufReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        // read directly into user buffer, if the buffer is larger
        if buf.len() > self.buf.capacity() && self.pos == self.cap {
            return self.reader.read(buf);
        }

        if self.pos >= self.cap {
            let end = self.buf.len();
            self.cap = self.reader.read(&mut self.buf.as_mut_slice()[0..end])?;
            self.pos = 0;
        }

        let end = cmp::min(self.cap, self.pos + buf.len());
        let res = end - self.pos;
        if end > self.pos {
            buf[0..res].copy_from_slice(&self.buf[self.pos..end]);
        }
        self.pos += res;
        Ok(res)
    }
}

impl<R: Read + Seek> Seek for BufReader<R> {
    fn seek(&mut self, off: usize, whence: SeekMode) -> Result<usize, Error> {
        if whence == SeekMode::Cur {
            // move buffer-internal position forward, but not beyond the buffer end
            let rem = self.cap - self.pos;
            self.pos += cmp::min(off, rem);
            // if the user wants to seek beyond the buffer end, do that with the underlying reader
            let rem_off = off.saturating_sub(rem);
            return if rem_off > 0 {
                self.reader.seek(rem_off, SeekMode::Cur)
            }
            // otherwise, just get the current position
            else {
                self.reader
                    .seek(0, SeekMode::Cur)
                    .map(|pos| pos - (self.cap - self.pos))
            };
        }

        // invalidate buffer
        self.pos = 0;
        self.cap = 0;
        self.reader.seek(off, whence)
    }
}

impl<R: Read + fmt::Debug> fmt::Debug for BufReader<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BufReader[reader={:?}, pos={}, cap={}]",
            self.reader, self.pos, self.cap
        )
    }
}

/// A writer implementation with an internal buffer
pub struct BufWriter<W: Write> {
    writer: W,
    buf: Vec<u8>,
    pos: usize,
}

impl<W: Write> BufWriter<W> {
    /// Creates a new `BufWriter` with the given writer
    pub fn new(writer: W) -> Self {
        Self::with_capacity(writer, 512)
    }

    /// Creates a new `BufWriter` with the given writer and a buffer with `cap` bytes
    pub fn with_capacity(writer: W, cap: usize) -> Self {
        Self {
            writer,
            buf: vec![0u8; cap],
            pos: 0,
        }
    }

    /// Returns a reference to the internal writer
    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    /// Returns a mutable reference to the internal writer
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    fn do_flush(&mut self) -> Result<(), Error> {
        if self.pos > 0 {
            self.writer.write(&self.buf[0..self.pos])?;
            self.pos = 0;
        }
        Ok(())
    }
}

impl<W: Write> Write for BufWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        // write directly from user buffer, if it is larger
        if buf.len() > self.buf.len() {
            self.do_flush()?;

            self.writer.write(buf)
        }
        else {
            let end = cmp::min(self.buf.len(), self.pos + buf.len());
            let res = end - self.pos;
            if end > self.pos {
                self.buf[self.pos..end].copy_from_slice(&buf[0..res]);
            }

            self.pos += res;

            // use line buffering
            if self.buf.iter().any(|b| *b == b'\n') {
                self.flush()?;
            }
            else if self.pos == self.buf.len() {
                self.do_flush()?;
            }

            Ok(res)
        }
    }

    fn flush(&mut self) -> Result<(), Error> {
        self.do_flush()?;
        self.writer.flush()
    }

    fn sync(&mut self) -> Result<(), Error> {
        self.writer.sync()
    }
}

impl<W: Write + Seek> Seek for BufWriter<W> {
    fn seek(&mut self, off: usize, whence: SeekMode) -> Result<usize, Error> {
        if whence != SeekMode::Cur || off != 0 {
            self.flush()?;
        }
        self.writer.seek(off, whence)
    }
}

impl<W: Write> Drop for BufWriter<W> {
    fn drop(&mut self) {
        self.flush().unwrap();
    }
}

impl<W: Write + fmt::Debug> fmt::Debug for BufWriter<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BufWriter[writer={:?}, pos={}]", self.writer, self.pos)
    }
}
