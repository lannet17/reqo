//! [`Writer`] and [`Reader`].

mod error;
mod reader;

pub use error::BufferError;
pub use reader::Reader;
use std::cmp::max;
use std::fmt::{Debug, Formatter};
use std::ops::Range;

#[allow(non_camel_case_types)]
pub type u24 = u32;

/// Byte buffer with fixed capacity. `start..end` holds written data that hasn't
/// been consumed; `end..capacity` is free.
pub struct Writer {
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

impl Default for Writer {
    fn default() -> Self { Writer::none() }
}

impl Clone for Writer {
    fn clone(&self) -> Self {
        Writer { buf: self.buf.clone(), start: self.start, end: self.end }
    }
}

impl Writer {
    pub const fn none() -> Writer {
        Writer { buf: Vec::new(), start: 0, end: 0 }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Writer { buf: vec![0; capacity], start: 0, end: 0 }
    }

    /// Double the capacity until it is at least `at_least`. Contents are kept.
    pub fn resize(&mut self, at_least: usize) -> Result<(), BufferError> {
        let mut capacity = max(self.capacity() * 2, 1);
        while capacity < at_least { capacity *= 2; }
        self.buf.resize(capacity, 0);
        Ok(())
    }

    pub fn truncate(&mut self, size: usize) {
        let start = self.start();
        let end = max(size - self.end(), start);
        self.reset_offset(start..end)
    }

    pub fn reset_offset(&mut self, offset: Range<usize>) {
        self.end = offset.end.min(self.capacity());
        self.start = offset.start;
    }

    pub fn filled(&self) -> &[u8] { &self.buf[self.start..self.end] }

    pub fn filled_mut(&mut self) -> &mut [u8] { &mut self.buf[self.start..self.end] }

    pub fn reset(&mut self) {
        self.start = 0;
        self.end = 0;
    }

    pub fn slice_at(&self, place: usize) -> &[u8] { &self.buf[place..self.end] }

    pub fn slice(&self, range: Range<usize>) -> &[u8] { &self.buf[range] }

    pub fn slice_mut(&mut self, range: Range<usize>) -> &mut [u8] { &mut self.buf[range] }

    /// Consume `size` bytes. When nothing is left, resets to 0 and returns `true`.
    pub fn used_empty(&mut self, size: usize) -> bool {
        self.start = (self.start + size).min(self.end);
        if self.start == self.end {
            self.reset();
            return true;
        }
        false
    }

    /// Move the bytes in `r` to `pos`. `end` becomes the end of the moved bytes;
    /// `start` moves with them if it was inside `r`.
    pub fn move_to(&mut self, r: Range<usize>, pos: usize) -> Result<(), BufferError> {
        if r.end < r.start || r.end > self.end() { return Err(BufferError::RangeEdgeError(r)); };
        let len = r.len();
        if pos + len > self.capacity() { return Err(BufferError::RangeEdgeError(r)); }
        self.buf.copy_within(r.clone(), pos);
        if r.start <= self.start { self.start = pos + (self.start - r.start); }
        self.end = pos + len;
        Ok(())
    }

    pub fn check_move(&mut self, need: usize) -> Result<(), BufferError> {
        if self.unfilled_len() >= need { return Ok(()); }
        if self.offset().start != 0 {
            self.move_to(self.offset(), 0)?;
        }
        if self.unfilled().is_empty() {
            return Err(BufferError::CapacityTooSmall {
                needed: need,
                current: self.capacity(),
                file: file!(),
                line: line!(),
            });
        }
        Ok(())
    }

    #[inline]
    pub fn capacity(&self) -> usize { self.buf.len() }

    #[inline]
    fn ensure(&self, place: usize, size: usize) -> Result<(), BufferError> {
        if place + size <= self.capacity() { return Ok(()); }
        Err(BufferError::CapacityTooSmall {
            current: self.capacity(),
            file: file!(),
            needed: place + size,
            line: line!(),
        })
    }

    #[inline]
    pub fn unfilled_len(&self) -> usize { self.capacity() - self.end }

    #[inline]
    pub const fn start(&self) -> usize { self.start }

    #[inline]
    pub const fn end(&self) -> usize { self.end }

    pub fn unfilled(&mut self) -> &mut [u8] {
        let end = self.end;
        &mut self.buf[end..]
    }

    #[inline]
    pub const fn is_empty(&self) -> bool { self.start == self.end }

    #[inline]
    pub const fn len(&self) -> usize { self.end - self.start }

    #[inline]
    pub fn add_len(&mut self, len: usize) {
        debug_assert!(self.end + len <= self.capacity());
        self.end += len;
    }

    #[inline]
    pub const fn offset(&self) -> Range<usize> { self.start..self.end }
}

impl Writer {
    pub fn write_slice(&mut self, v: &[u8]) -> Result<(), BufferError> {
        self.ensure(self.end, v.len())?;
        self.buf[self.end..self.end + v.len()].copy_from_slice(v);
        self.end += v.len();
        Ok(())
    }

    /// Write at `place`. `start` and `end` don't change.
    pub fn write_slice_in(&mut self, place: usize, v: &[u8]) -> Result<usize, BufferError> {
        self.ensure(place, v.len())?;
        self.buf[place..place + v.len()].copy_from_slice(v);
        Ok(v.len())
    }

    pub fn write_u8(&mut self, v: u8) -> Result<(), BufferError> { self.write_slice(&[v]) }

    pub fn write_u16(&mut self, v: u16) -> Result<(), BufferError> { self.write_slice(&v.to_be_bytes()) }

    pub fn write_u24(&mut self, v: u24) -> Result<(), BufferError> { self.write_slice(&v.to_be_bytes()[1..]) }

    pub fn write_u32(&mut self, v: u32) -> Result<(), BufferError> { self.write_slice(&v.to_be_bytes()) }

    pub fn write_u64(&mut self, v: u64) -> Result<(), BufferError> { self.write_slice(&v.to_be_bytes()) }

    /// `write_u16_be(v.to_be())` is the same as `write_u16(v)`.
    pub fn write_u16_be(&mut self, v: u16) -> Result<(), BufferError> { self.write_u16(u16::from_be(v)) }

    pub fn write_u24_be(&mut self, v: u24) -> Result<(), BufferError> { self.write_u24(u32::from_be(v)) }

    pub fn write_u32_be(&mut self, v: u32) -> Result<(), BufferError> { self.write_u32(u32::from_be(v)) }

    pub fn write_u64_be(&mut self, v: u64) -> Result<(), BufferError> { self.write_u64(u64::from_be(v)) }

    pub fn write_u16_in(&mut self, place: usize, n: u16) -> Result<(), BufferError> {
        self.write_slice_in(place, &n.to_be_bytes())?;
        Ok(())
    }

    pub fn write_u24_in(&mut self, place: usize, v: u24) -> Result<usize, BufferError> {
        self.write_slice_in(place, &v.to_be_bytes()[1..])
    }

    pub fn write_u24_be_in(&mut self, place: usize, v: u24) -> Result<usize, BufferError> {
        self.write_u24_in(place, u32::from_be(v))
    }

    pub fn extend_from_slice(&mut self, buf: &[u8]) -> Result<(), BufferError> {
        if self.unfilled_len() < buf.len() {
            self.resize(self.end + buf.len())?;
        }
        self.write_slice(buf)
    }

    pub fn write_zero(&mut self, size: usize) -> Result<(), BufferError> {
        self.ensure(self.end, size)?;
        self.buf[self.end..self.end + size].fill(0);
        self.end += size;
        Ok(())
    }
}

/// Write before `start` (leave room first with `reset_offset`).
impl Writer {
    pub fn write_u8_front(&mut self, v: u8) -> usize {
        self.start -= 1;
        self.buf[self.start] = v;
        1
    }

    pub fn write_u16_front(&mut self, v: u16) -> usize {
        self.start -= 2;
        self.buf[self.start..self.start + 2].copy_from_slice(&v.to_be_bytes());
        2
    }

    pub fn writer_u32_front(&mut self, v: u32) -> usize {
        self.start -= 4;
        self.buf[self.start..self.start + 4].copy_from_slice(&v.to_be_bytes());
        4
    }

    pub fn writer_u64_front(&mut self, v: u64) -> usize {
        self.start -= 8;
        self.buf[self.start..self.start + 8].copy_from_slice(&v.to_be_bytes());
        8
    }

    pub fn write_slice_front(&mut self, v: &[u8]) -> Result<usize, BufferError> {
        self.start -= v.len();
        self.write_slice_in(self.start, v)
    }
}

impl std::io::Write for Writer {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.write_slice(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

impl Debug for Writer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.filled()))
    }
}

/// Borrowed or owned bytes.
#[derive(Clone)]
pub enum Buf<'a> {
    Ref {
        cap: usize,
        inner: &'a [u8],
    },
    Vec(Vec<u8>),
}

impl<'a> Default for Buf<'a> {
    fn default() -> Self { Buf::new_ref(&[]) }
}

impl<'a> Buf<'a> {
    pub const fn new_ref(val: &'a [u8]) -> Buf<'a> { Buf::Ref { cap: 0, inner: val } }

    pub const fn is_empty(&self) -> bool { self.len() == 0 }

    pub const fn len(&self) -> usize {
        match self {
            Buf::Ref { inner, .. } => inner.len(),
            Buf::Vec(v) => v.len(),
        }
    }

    pub const fn as_slice(&self) -> &[u8] {
        match self {
            Buf::Ref { inner, .. } => inner,
            Buf::Vec(inner) => inner.as_slice(),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> { self.as_slice().to_vec() }

    pub fn into_vec(self) -> Vec<u8> {
        match self {
            Buf::Ref { inner, .. } => inner.to_vec(),
            Buf::Vec(v) => v,
        }
    }
}

impl<'a> AsRef<[u8]> for Buf<'a> {
    fn as_ref(&self) -> &[u8] { self.as_slice() }
}

impl<'a> Debug for Buf<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", hex::encode(self.as_slice()))
    }
}

#[cfg(test)]
mod test_buffer {
    use crate::Writer;

    #[test]
    fn buffer_test() {
        let mut buffer = Writer::with_capacity(1024);
        buffer.write_slice(&[1, 2, 3, 4, 5]).unwrap();
        assert_eq!(buffer.filled(), [1, 2, 3, 4, 5]);
        buffer.used_empty(1);
        assert_eq!(buffer.filled(), [2, 3, 4, 5]);
        assert_eq!(buffer.unfilled().len(), 1019);

        buffer.move_to(3..buffer.offset().end, 2).unwrap();
        assert_eq!(buffer.filled(), [2, 4, 5]);
        assert_eq!(buffer.offset(), 1..4);
        buffer.move_to(buffer.offset(), 0).unwrap();
        assert_eq!(buffer.filled(), [2, 4, 5]);
        assert_eq!(buffer.offset(), 0..3);

        buffer.resize(2048).unwrap();
        assert_eq!(buffer.capacity(), 2048);
    }

    #[test]
    fn endian_test() {
        let mut w = Writer::with_capacity(32);
        w.write_u16(0x0102).unwrap();
        w.write_u24(0x030405).unwrap();
        w.write_u32(0x06070809).unwrap();
        w.write_u16_be(0x0a0bu16.to_be()).unwrap();
        assert_eq!(w.filled(), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        w.write_u24_in(0, 0xaabbcc).unwrap();
        assert_eq!(&w.filled()[..3], [0xaa, 0xbb, 0xcc]);
    }
}
