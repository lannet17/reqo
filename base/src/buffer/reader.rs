use crate::{BufferError, u24};

/// Big-endian cursor over a borrowed byte slice.
#[derive(Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub const fn from_slice(slice: &'a [u8]) -> Reader<'a> {
        Reader { buf: slice, pos: 0 }
    }

    #[inline]
    fn take<const N: usize>(&mut self) -> Result<[u8; N], BufferError> {
        let s = self.read_slice(N)?;
        Ok(s.try_into().expect("length checked"))
    }

    pub fn read_u8(&mut self) -> Result<u8, BufferError> {
        if self.pos >= self.buf.len() { return Err(BufferError::Insufficient); }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_u16(&mut self) -> Result<u16, BufferError> { Ok(u16::from_be_bytes(self.take()?)) }

    pub fn read_u24(&mut self) -> Result<u24, BufferError> {
        let [a, b, c] = self.take::<3>()?;
        Ok(u32::from_be_bytes([0, a, b, c]))
    }

    pub fn read_u32(&mut self) -> Result<u32, BufferError> { Ok(u32::from_be_bytes(self.take()?)) }

    pub fn read_u64(&mut self) -> Result<u64, BufferError> { Ok(u64::from_be_bytes(self.take()?)) }

    pub fn read_u16_le(&mut self) -> Result<u16, BufferError> { Ok(u16::from_le_bytes(self.take()?)) }

    pub fn read_u24_le(&mut self) -> Result<u24, BufferError> {
        let [a, b, c] = self.take::<3>()?;
        Ok(u32::from_le_bytes([a, b, c, 0]))
    }

    pub fn read_u32_le(&mut self) -> Result<u32, BufferError> { Ok(u32::from_le_bytes(self.take()?)) }

    pub fn read_u64_le(&mut self) -> Result<u64, BufferError> { Ok(u64::from_le_bytes(self.take()?)) }

    pub fn read_slice(&mut self, size: usize) -> Result<&'a [u8], BufferError> {
        if size > self.unread_len() {
            return Err(BufferError::IndexOutBound { index: self.pos, want: size, size: self.buf.len() });
        }
        let s = &self.buf[self.pos..self.pos + size];
        self.pos += size;
        Ok(s)
    }

    pub fn read_reader(&mut self, size: usize) -> Result<Reader<'a>, BufferError> {
        Ok(Reader::from_slice(self.read_slice(size)?))
    }

    pub fn read_str(&mut self, size: usize) -> Result<&'a str, BufferError> {
        Ok(std::str::from_utf8(self.read_slice(size)?)?)
    }

    pub const fn size(&self) -> usize { self.buf.len() }

    pub const fn unread_len(&self) -> usize { self.buf.len() - self.pos }

    pub fn unread(&self) -> &'a [u8] { &self.buf[self.pos..] }

    pub fn add_len(&mut self, size: usize) { self.pos += size; }

    pub const fn position(&self) -> usize { self.pos }

    pub fn set_position(&mut self, pos: usize) { self.pos = pos; }

    pub fn inner(&self) -> &'a [u8] { self.buf }

    pub fn find<P: FnMut(&u8) -> bool>(&self, predicate: P) -> Option<usize> {
        self.buf[self.pos..].iter().position(predicate)
    }

    pub fn read_to(&mut self, end: &[u8]) -> Option<&'a [u8]> {
        let unread = &self.buf[self.pos..];
        let pos = unread.windows(end.len()).position(|window| window == end)?;
        self.pos += pos;
        Some(&unread[..pos])
    }

    pub fn current(&self) -> Result<u8, BufferError> {
        self.buf.get(self.pos).copied().ok_or(BufferError::IndexOutBound {
            index: self.pos,
            want: 1,
            size: self.buf.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Reader;

    #[test]
    fn test_reader() {
        let buf = [12, 23, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18];
        let mut reader = Reader::from_slice(&buf);
        assert_eq!(reader.read_u8().unwrap(), 12);
        assert_eq!(reader.read_u16().unwrap(), 5891);
        assert_eq!(reader.read_u24().unwrap(), 263430);
        assert_eq!(reader.read_u32().unwrap(), 117967114);
        assert_eq!(reader.read_u64().unwrap(), 796025588171149586);
        assert!(reader.read_u8().is_err());
    }
}
