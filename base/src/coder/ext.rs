use crate::{Reader, Writer};
use crate::error::BaseResult;

pub trait StreamDecode {
    fn decompress(&mut self, reader: &mut Reader<'_>, out: &mut Writer) -> BaseResult<bool>;
    fn flush(&mut self, out: &mut Writer) -> BaseResult<bool>;
}

pub trait StreamEncode {
    fn compress(&mut self, reader: &mut Reader<'_>, out: &mut Writer) -> BaseResult<bool>;
    fn flush(&mut self, out: &mut Writer) -> BaseResult<bool>;
}
