//! gzip, deflate, zlib, brotli and zstd. zstd needs the `zstd` feature
//! (the `zstd` crate, which builds libzstd).

mod chunk;
mod ext;

use crate::error::{BaseError, BaseResult};
use crate::{Buffer, Reader, UrlError, Writer};
pub use chunk::ChunkDecoder;
pub use ext::{StreamDecode, StreamEncode};
use flate2::{Compression, Decompress, FlushDecompress, Status};
use std::borrow::Cow;
use std::io::Write;

pub fn url_encode<'a>(url: impl Into<Cow<'a, str>>) -> Cow<'a, str> {
    let url = url.into();
    match urlencoding::encode(url.as_ref()) {
        Cow::Borrowed(_) => url,
        Cow::Owned(v) => Cow::Owned(v),
    }
}

pub fn url_decode<'a>(url: impl Into<Cow<'a, str>>) -> Result<Cow<'a, str>, UrlError> {
    let url = url.into();
    match urlencoding::decode(url.as_ref())? {
        Cow::Borrowed(_) => Ok(url),
        Cow::Owned(v) => Ok(Cow::Owned(v)),
    }
}

pub fn chunk_decode(mut raw: Vec<u8>) -> BaseResult<Vec<u8>> {
    let mut res = Vec::with_capacity(raw.len());
    while let Some(pos) = raw.windows(2).position(|w| w == b"\r\n") {
        let len_bs = raw.drain(..pos).collect();
        let len_str = String::from_utf8(len_bs)?;
        raw.drain(..2);
        let chunk_len = usize::from_str_radix(len_str.as_str(), 16)?;
        res.extend(raw.drain(..chunk_len).collect::<Vec<_>>());
        raw.drain(..2);
    }
    Ok(res)
}

macro_rules! one_shot {
    ($($comp:ident, $decomp:ident => $typ:expr;)*) => {$(
        #[inline]
        pub fn $comp(buf: impl AsRef<[u8]>) -> BaseResult<Buffer> { compress(buf.as_ref(), $typ) }
        #[inline]
        pub fn $decomp(buf: impl AsRef<[u8]>) -> BaseResult<Buffer> { decompress(buf.as_ref(), $typ) }
    )*};
}

one_shot! {
    gzip_compress, gzip_decompress => CodeType::Gzip;
    deflate_compress, deflate_decompress => CodeType::Deflate;
    zlib_compress, zlib_decompress => CodeType::Zlib;
    br_compress, br_decompress => CodeType::Brotli;
    zstd_compress, zstd_decompress => CodeType::Zstd;
}

fn compress(buf: &[u8], typ: CodeType) -> BaseResult<Buffer> {
    let mut coder = TZCoder::new_compress(typ)?;
    let mut reader = Reader::from_slice(buf);
    let mut out = Writer::with_capacity(buf.len().max(64));
    coder.update(&mut reader, &mut out)?;
    coder.finish(&mut out)?;
    Ok(out)
}

fn decompress(buf: &[u8], typ: CodeType) -> BaseResult<Buffer> {
    if buf.is_empty() { return Ok(Buffer::none()); }
    let mut reader = Reader::from_slice(buf);
    let mut out = Writer::with_capacity(buf.len() * 2);
    let mut coder = TZCoder::new_decompress(typ)?;
    coder.update(&mut reader, &mut out)?;
    coder.finish(&mut out)?;
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CodeType {
    Gzip = 0,
    /// Raw deflate (RFC 1951). Used by WebSocket permessage-deflate.
    Deflate = 1,
    Brotli = 2,
    /// zlib (RFC 1950). This is what HTTP `Content-Encoding: deflate` uses.
    Zlib = 3,
    Zstd = 4,
    Null = 5,
}

// gzip header and trailer around a raw inflater
struct GzipState {
    header: Vec<u8>,
    header_done: bool,
    trailer_left: usize,
}

impl GzipState {
    fn new() -> Self { GzipState { header: Vec::with_capacity(16), header_done: false, trailer_left: 8 } }

    /// Feed bytes until the header is complete; returns how many bytes were consumed.
    fn feed_header(&mut self, input: &[u8]) -> BaseResult<usize> {
        for (i, b) in input.iter().enumerate() {
            self.header.push(*b);
            if let Some(done) = Self::header_len(&self.header)? {
                debug_assert_eq!(done, self.header.len());
                self.header_done = true;
                return Ok(i + 1);
            }
        }
        Ok(input.len())
    }

    /// `Ok(Some(n))` when `h` is exactly a full header of length n.
    fn header_len(h: &[u8]) -> BaseResult<Option<usize>> {
        if h.len() < 10 { return Ok(None); }
        if h[0] != 0x1f || h[1] != 0x8b || h[2] != 8 { return Err("invalid gzip header".into()); }
        let flg = h[3];
        let mut pos = 10;
        if flg & 0x04 != 0 {
            if h.len() < pos + 2 { return Ok(None); }
            pos += 2 + u16::from_le_bytes([h[pos], h[pos + 1]]) as usize;
        }
        for bit in [0x08u8, 0x10] {
            if flg & bit != 0 {
                match h.get(pos..).and_then(|s| s.iter().position(|b| *b == 0)) {
                    Some(z) => pos += z + 1,
                    None => return Ok(None),
                }
            }
        }
        if flg & 0x02 != 0 { pos += 2; }
        Ok(if h.len() == pos { Some(pos) } else { None })
    }
}

enum Decoder {
    Null,
    Inflate { inner: Decompress, gzip: Option<GzipState>, done: bool },
    Brotli { state: Box<brotli::BrotliState<brotli::HeapAlloc<u8>, brotli::HeapAlloc<u32>, brotli::HeapAlloc<brotli::HuffmanCode>>>, done: bool },
    #[cfg(feature = "zstd")]
    Zstd { inner: zstd::stream::raw::Decoder<'static>, done: bool },
}

enum Encoder {
    Null,
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
    Deflate(flate2::write::DeflateEncoder<Vec<u8>>),
    Zlib(flate2::write::ZlibEncoder<Vec<u8>>),
    Brotli(Option<Box<brotli::CompressorWriter<Vec<u8>>>>),
    #[cfg(feature = "zstd")]
    Zstd(Option<zstd::stream::write::Encoder<'static, Vec<u8>>>),
}

enum Inner {
    Dec(Decoder),
    Enc(Encoder),
}

/// Streaming encoder or decoder.
pub struct TZCoder {
    typ: CodeType,
    inner: Inner,
}

// The zstd contexts are only touched through `&mut self`, so sharing `&TZCoder`
// across threads cannot race.
unsafe impl Sync for TZCoder {}
unsafe impl Send for TZCoder {}

impl TZCoder {
    pub fn code_type(&self) -> CodeType { self.typ }

    pub fn new_decompress(typ: CodeType) -> BaseResult<TZCoder> {
        let dec = match typ {
            CodeType::Null => Decoder::Null,
            CodeType::Deflate => Decoder::Inflate { inner: Decompress::new(false), gzip: None, done: false },
            CodeType::Zlib => Decoder::Inflate { inner: Decompress::new(true), gzip: None, done: false },
            CodeType::Gzip => Decoder::Inflate { inner: Decompress::new(false), gzip: Some(GzipState::new()), done: false },
            CodeType::Brotli => Decoder::Brotli {
                state: Box::new(brotli::BrotliState::new(
                    brotli::HeapAlloc::default(),
                    brotli::HeapAlloc::default(),
                    brotli::HeapAlloc::default(),
                )),
                done: false,
            },
            #[cfg(feature = "zstd")]
            CodeType::Zstd => Decoder::Zstd { inner: zstd::stream::raw::Decoder::new()?, done: false },
            #[cfg(not(feature = "zstd"))]
            CodeType::Zstd => return Err("zstd support is disabled (enable the `zstd` feature)".into()),
        };
        Ok(TZCoder { typ, inner: Inner::Dec(dec) })
    }

    pub fn new_compress(typ: CodeType) -> BaseResult<TZCoder> {
        let level = Compression::default();
        let enc = match typ {
            CodeType::Null => Encoder::Null,
            CodeType::Gzip => Encoder::Gzip(flate2::write::GzEncoder::new(Vec::new(), level)),
            CodeType::Deflate => Encoder::Deflate(flate2::write::DeflateEncoder::new(Vec::new(), level)),
            CodeType::Zlib => Encoder::Zlib(flate2::write::ZlibEncoder::new(Vec::new(), level)),
            CodeType::Brotli => Encoder::Brotli(Some(Box::new(brotli::CompressorWriter::new(Vec::new(), 4096, 11, 22)))),
            #[cfg(feature = "zstd")]
            CodeType::Zstd => Encoder::Zstd(Some(zstd::stream::write::Encoder::new(Vec::new(), 3)?)),
            #[cfg(not(feature = "zstd"))]
            CodeType::Zstd => return Err("zstd support is disabled (enable the `zstd` feature)".into()),
        };
        Ok(TZCoder { typ, inner: Inner::Enc(enc) })
    }

    /// Process all of `reader` and append the output to `out`, growing it if needed.
    /// For decoders, returns `true` when the end of the compressed stream is reached.
    pub fn update(&mut self, reader: &mut Reader<'_>, out: &mut Writer) -> BaseResult<bool> {
        match &mut self.inner {
            Inner::Dec(dec) => Self::decode(dec, reader, out),
            Inner::Enc(enc) => {
                let input = reader.unread();
                reader.add_len(input.len());
                Self::encode(enc, input, out)?;
                Ok(false)
            }
        }
    }

    /// Write remaining output. Ends the stream for encoders.
    pub fn finish(&mut self, out: &mut Writer) -> BaseResult<bool> {
        match &mut self.inner {
            Inner::Dec(dec) => Ok(match dec {
                Decoder::Null => true,
                Decoder::Inflate { done, .. } | Decoder::Brotli { done, .. } => *done,
                #[cfg(feature = "zstd")]
                Decoder::Zstd { done, .. } => *done,
            }),
            Inner::Enc(enc) => {
                let tail = match enc {
                    Encoder::Null => Vec::new(),
                    Encoder::Gzip(e) => { e.try_finish()?; std::mem::take(e.get_mut()) }
                    Encoder::Deflate(e) => { e.try_finish()?; std::mem::take(e.get_mut()) }
                    Encoder::Zlib(e) => { e.try_finish()?; std::mem::take(e.get_mut()) }
                    Encoder::Brotli(e) => e.take().map(|e| e.into_inner()).unwrap_or_default(),
                    #[cfg(feature = "zstd")]
                    Encoder::Zstd(e) => match e.take() {
                        Some(e) => e.finish()?,
                        None => Vec::new(),
                    },
                };
                out.extend_from_slice(&tail)?;
                Ok(true)
            }
        }
    }

    fn encode(enc: &mut Encoder, input: &[u8], out: &mut Writer) -> BaseResult<()> {
        let produced = match enc {
            Encoder::Null => return Ok(out.extend_from_slice(input)?),
            Encoder::Gzip(e) => { e.write_all(input)?; std::mem::take(e.get_mut()) }
            Encoder::Deflate(e) => { e.write_all(input)?; std::mem::take(e.get_mut()) }
            Encoder::Zlib(e) => { e.write_all(input)?; std::mem::take(e.get_mut()) }
            Encoder::Brotli(e) => {
                let e = e.as_mut().ok_or("brotli encoder already finished")?;
                e.write_all(input)?;
                std::mem::take(e.get_mut())
            }
            #[cfg(feature = "zstd")]
            Encoder::Zstd(e) => {
                let e = e.as_mut().ok_or("zstd encoder already finished")?;
                e.write_all(input)?;
                std::mem::take(e.get_mut())
            }
        };
        out.extend_from_slice(&produced)?;
        Ok(())
    }

    fn grow(out: &mut Writer, hint: usize) -> BaseResult<()> {
        if out.unfilled_len() < 256 {
            out.resize(out.capacity() + hint.max(1024))?;
        }
        Ok(())
    }

    fn decode(dec: &mut Decoder, reader: &mut Reader<'_>, out: &mut Writer) -> BaseResult<bool> {
        match dec {
            Decoder::Null => {
                let input = reader.unread();
                reader.add_len(input.len());
                out.extend_from_slice(input)?;
                Ok(false)
            }
            Decoder::Inflate { inner, gzip, done } => {
                loop {
                    if *done {
                        // Swallow the gzip trailer (crc32 + isize) and any padding.
                        if let Some(gz) = gzip {
                            let skip = gz.trailer_left.min(reader.unread_len());
                            gz.trailer_left -= skip;
                            reader.add_len(skip);
                        }
                        reader.add_len(reader.unread_len());
                        return Ok(true);
                    }
                    if let Some(gz) = gzip {
                        if !gz.header_done {
                            let used = gz.feed_header(reader.unread())?;
                            reader.add_len(used);
                            if !gz.header_done { return Ok(false); }
                        }
                    }
                    Self::grow(out, reader.unread_len() * 2)?;
                    let before_in = inner.total_in();
                    let before_out = inner.total_out();
                    let status = inner.decompress(reader.unread(), out.unfilled(), FlushDecompress::Sync)
                        .map_err(|e| BaseError::Coder(e.to_string()))?;
                    let used = (inner.total_in() - before_in) as usize;
                    let wrote = (inner.total_out() - before_out) as usize;
                    reader.add_len(used);
                    out.add_len(wrote);
                    match status {
                        Status::StreamEnd => *done = true,
                        Status::Ok | Status::BufError => {
                            if reader.unread_len() == 0 && out.unfilled_len() > 0 { return Ok(false); }
                            if used == 0 && wrote == 0 && out.unfilled_len() > 0 { return Ok(false); }
                        }
                    }
                }
            }
            Decoder::Brotli { state, done } => {
                use brotli::BrotliResult;
                loop {
                    if *done {
                        reader.add_len(reader.unread_len());
                        return Ok(true);
                    }
                    Self::grow(out, reader.unread_len() * 4)?;
                    let input = reader.unread();
                    let mut avail_in = input.len();
                    let mut in_off = 0;
                    let end = out.end();
                    let mut avail_out = out.unfilled_len();
                    let mut out_off = 0;
                    let mut total = 0;
                    let res = brotli::BrotliDecompressStream(
                        &mut avail_in, &mut in_off, input,
                        &mut avail_out, &mut out_off, out.unfilled(),
                        &mut total, state,
                    );
                    reader.add_len(in_off);
                    out.add_len(out_off);
                    debug_assert_eq!(out.end(), end + out_off);
                    match res {
                        BrotliResult::ResultSuccess => *done = true,
                        BrotliResult::NeedsMoreInput => return Ok(false),
                        BrotliResult::NeedsMoreOutput => continue,
                        BrotliResult::ResultFailure => return Err(BaseError::Coder("brotli decode failed".into())),
                    }
                }
            }
            #[cfg(feature = "zstd")]
            Decoder::Zstd { inner, done } => {
                use zstd::stream::raw::{InBuffer, Operation, OutBuffer};
                loop {
                    if *done {
                        reader.add_len(reader.unread_len());
                        return Ok(true);
                    }
                    Self::grow(out, reader.unread_len() * 4)?;
                    let mut src = InBuffer::around(reader.unread());
                    let mut dst = OutBuffer::around(out.unfilled());
                    let hint = inner.run(&mut src, &mut dst)?;
                    let (used, wrote) = (src.pos(), dst.pos());
                    reader.add_len(used);
                    out.add_len(wrote);
                    if hint == 0 { *done = true; continue; }
                    if reader.unread_len() == 0 && out.unfilled_len() > 0 { return Ok(false); }
                }
            }
        }
    }
}

impl StreamDecode for TZCoder {
    fn decompress(&mut self, reader: &mut Reader<'_>, out: &mut Writer) -> BaseResult<bool> {
        self.update(reader, out)
    }

    fn flush(&mut self, out: &mut Writer) -> BaseResult<bool> {
        self.finish(out)
    }
}

impl StreamEncode for TZCoder {
    fn compress(&mut self, reader: &mut Reader<'_>, out: &mut Writer) -> BaseResult<bool> {
        self.update(reader, out)
    }

    fn flush(&mut self, out: &mut Writer) -> BaseResult<bool> {
        self.finish(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &[u8] = b"sdfsdfklllllllllllllllllllljsdfsdfkhsdkfhsdfsdfsdfyt7ujsre";

    #[test]
    fn test_br_decompress_chunked() {
        let compressed = [27, 59, 0, 248, 197, 109, 108, 188, 35, 42, 217, 147, 70, 37, 10, 74, 145, 67, 2, 167, 136, 88, 56, 154, 148, 111, 44, 175, 176, 152, 63, 84, 220, 226, 158, 42, 46, 44, 40, 152, 60, 14];
        for chunk_size in 1..8 {
            let mut coder = TZCoder::new_decompress(CodeType::Brotli).unwrap();
            let mut out = Writer::with_capacity(1);
            for chunk in compressed.chunks(chunk_size) {
                coder.update(&mut Reader::from_slice(chunk), &mut out).unwrap();
            }
            assert!(coder.finish(&mut out).unwrap());
            assert_eq!(out.filled(), b"dfjsdkgfsdhkgjksfyhdlfusdhgfkyudsgflsduyfgsdukfsdfgdhfgjhjhk");
        }
    }

    #[test]
    fn test_gzip_decompress() {
        let compressed = [31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 109, 137, 177, 13, 0, 32, 12, 195, 206, 226, 161, 16, 85, 45, 19, 129, 129, 239, 169, 212, 181, 150, 23, 203, 2, 5, 198, 106, 112, 213, 51, 33, 104, 21, 233, 59, 227, 186, 246, 252, 93, 161, 13, 5, 58, 0, 0, 0];
        for chunk_size in [1, 3, 7, compressed.len()] {
            let mut coder = TZCoder::new_decompress(CodeType::Gzip).unwrap();
            let mut out = Buffer::with_capacity(1);
            let mut finish = false;
            for chunk in compressed.chunks(chunk_size) {
                let mut r = Reader::from_slice(chunk);
                finish = coder.update(&mut r, &mut out).unwrap();
                assert_eq!(r.unread_len(), 0);
            }
            assert!(finish);
            assert_eq!(out.filled(), TEXT);
        }
    }

    #[test]
    fn test_deflate_decompress() {
        let compressed = [109, 137, 177, 13, 0, 32, 12, 195, 206, 226, 161, 16, 85, 45, 19, 129, 129, 239, 169, 212, 181, 150, 23, 203, 2, 5, 198, 106, 112, 213, 51, 33, 104, 21, 233, 59, 227, 186, 246, 252];
        let mut decoder = TZCoder::new_decompress(CodeType::Deflate).unwrap();
        let mut out = Writer::with_capacity(1024);
        decoder.update(&mut Reader::from_slice(&compressed), &mut out).unwrap();
        assert_eq!(out.filled(), TEXT);
    }

    #[test]
    fn test_zstd_decompress() {
        let compressed = [40, 181, 47, 253, 32, 37, 41, 1, 0, 115, 100, 102, 104, 115, 100, 102, 115, 100, 103, 103, 106, 121, 117, 116, 101, 114, 100, 102, 116, 116, 104, 102, 103, 98, 104, 106, 104, 104, 103, 115, 100, 102, 103, 100, 103, 102];
        let mut coder = TZCoder::new_decompress(CodeType::Zstd).unwrap();
        let mut out = Buffer::with_capacity(20);
        assert!(coder.update(&mut Reader::from_slice(&compressed), &mut out).unwrap());
        assert_eq!(out.filled(), b"sdfhsdfsdggjyuterdftthfgbhjhhgsdfgdgf");
    }

    #[test]
    fn test_roundtrip() {
        for typ in [CodeType::Gzip, CodeType::Deflate, CodeType::Zlib, CodeType::Brotli, CodeType::Zstd, CodeType::Null] {
            let c = compress(TEXT, typ).unwrap();
            let d = decompress(c.filled(), typ).unwrap();
            assert_eq!(d.filled(), TEXT, "{typ:?}");
        }
    }

    #[test]
    fn test_ws_sync_flush() {
        // permessage-deflate: raw deflate, each message ends with a sync flush (00 00 ff ff)
        let mut enc = flate2::Compress::new(Compression::default(), false);
        let mut buf = vec![0u8; 256];
        enc.compress(b"hello", &mut buf, flate2::FlushCompress::Sync).unwrap();
        let n = enc.total_out() as usize;
        assert_eq!(&buf[n - 4..n], [0, 0, 0xff, 0xff]);
        let mut dec = TZCoder::new_decompress(CodeType::Deflate).unwrap();
        let mut out = Writer::with_capacity(8);
        dec.update(&mut Reader::from_slice(&buf[..n - 4]), &mut out).unwrap();
        dec.update(&mut Reader::from_slice(&[0, 0, 0xff, 0xff]), &mut out).unwrap();
        assert_eq!(out.filled(), b"hello");
    }
}
