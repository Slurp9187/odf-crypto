//! Keeps the caller's own I/O failure apart from the zip crate's verdict.
//!
//! `zip` folds every `io::Error` into `ZipError::Io`, including the
//! `UnexpectedEof` it raises itself when a well-behaved reader runs out of a
//! truncated archive. Those two mean different things to a caller: the second
//! is a statement about the file (`NotZip`, `Zip`), the first is the caller's
//! reader refusing -- a cancel, a dropped network share -- and says nothing
//! about the file at all. Reporting a cancel as "not a zip archive" is the
//! wrong answer, and so is reporting a truncated file as an I/O failure.
//!
//! So the reader is wrapped, and the wrapper keeps the first error the
//! **caller's** reader returned. If it holds one when the call ends, that error
//! is the result, whatever the zip crate made of it -- including when the zip
//! crate swallowed it and carried on, because a classification read past a
//! failed read is a classification of bytes nobody saw.
//!
//! A `Cursor` over a slice never fails a read (it returns `Ok(0)` at the end),
//! so the whole-buffer entry points can never reach the latch. That is what
//! keeps `classify(&[u8])`'s errors exactly what they were.

use std::cell::Cell;
use std::io::{self, Read, Seek, SeekFrom};

/// The slot a [`Latched`] reader reports into. Lives on the caller's stack, so
/// it outlives the zip archive that consumes the reader.
#[derive(Default)]
pub(crate) struct Latch(Cell<Option<io::Error>>);

impl Latch {
    /// The caller's first reader error, if there was one.
    pub(crate) fn take(&self) -> Option<io::Error> {
        self.0.take()
    }

    /// Keep `err` -- the caller's own value, so a caller can downcast its cancel
    /// error back out -- and hand the zip crate a stand-in of the same kind.
    /// `io::Error` is not `Clone`, and the zip crate may drop what it is given.
    fn record(&self, err: io::Error) -> io::Error {
        let stand_in = io::Error::new(err.kind(), "the reader failed");
        // First error wins: a zip crate retrying after a failure must not
        // replace the cause with a consequence.
        let first = self.0.take();
        self.0.set(Some(first.unwrap_or(err)));
        stand_in
    }
}

/// A reader whose failures are recorded in a [`Latch`] before the zip crate
/// sees them.
pub(crate) struct Latched<'a, R> {
    inner: R,
    latch: &'a Latch,
}

impl<'a, R> Latched<'a, R> {
    pub(crate) fn new(inner: R, latch: &'a Latch) -> Self {
        Self { inner, latch }
    }
}

impl<R: Read> Read for Latched<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).map_err(|e| self.latch.record(e))
    }
}

impl<R: Seek> Seek for Latched<'_, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos).map_err(|e| self.latch.record(e))
    }
}
