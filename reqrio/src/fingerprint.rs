//! HTTP/2 (and HTTP/3) SETTINGS frames and stream priority. The TLS ClientHello
//! is up to the [`TlsConnector`](crate::tls::TlsConnector).

use crate::*;

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct H2Finger {
    /// Frames sent after the connection preface.
    pub frames: Vec<H2Frame<'static>>,
    pub weight: u8,
    pub priority: bool,
}

impl Default for H2Finger {
    fn default() -> Self {
        H2Finger {
            frames: vec![
                H2Frame::new_setting(vec![
                    H2Setting::HeaderTableSize(65536),
                    H2Setting::EnablePush(0),
                    H2Setting::InitialWindowSize(6291456),
                    H2Setting::MaxHeaderListSize(242144)
                ]),
                H2Frame::new_window_update(2147418112)
            ],
            weight: 147,
            priority: true,
        }
    }
}

impl H2Finger {
    pub fn build_settings(&self, writer: &mut Writer) -> Result<(), BufferError> {
        for frame in self.frames.iter() {
            frame.write_to(writer)?;
        }
        Ok(())
    }

    pub fn add_frame(&mut self, frame: H2Frame<'static>) {
        self.frames.push(frame)
    }

    pub fn set_priority(&mut self, priority: bool, weight: u8) {
        self.priority = priority;
        self.weight = weight;
    }

    pub fn with_priority(mut self, priority: bool, weight: u8) -> Self {
        self.set_priority(priority, weight);
        self
    }
}

/// H3 frames; used only for the post-handshake `settings` stream.
#[cfg(feature = "quic")]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct H3Finger {
    pub frames: Vec<H3Frame<'static>>,
}

#[cfg(feature = "quic")]
impl H3Finger {
    pub fn build_settings(&self, writer: &mut Writer) -> Result<(), BufferError> {
        for frame in self.frames.iter() {
            frame.write_to(writer)?;
        }
        Ok(())
    }
}

#[cfg(feature = "quic")]
impl Default for H3Finger {
    fn default() -> Self {
        H3Finger {
            frames: vec![
                H3Frame {
                    typ: H3FrameType::Setting,
                    payload: H3Payload::Settings(vec![
                        H3Setting::new(H3Setting::MaxTableCapacity, 65536),
                        H3Setting::new(H3Setting::MaxFieldSectionSize, 262144),
                        H3Setting::new(H3Setting::BlockedStreams, 100),
                        H3Setting::new(H3Setting::EnableDatagram, 1),
                        H3Setting::new(0x7c3b6e5b0, 4089453656)
                    ])
                },
                H3Frame {
                    typ: H3FrameType::new(0x11d4c4c93c),
                    payload: H3Payload::Bytes(Buf::new_ref(&[0x54]))
                },
            ],
        }
    }
}


/// HTTP/2 (and HTTP/3) settings used by a session.
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Default)]
pub struct Fingerprint {
    h2: H2Finger,
    #[cfg(feature = "quic")]
    h3: H3Finger,
}

impl Fingerprint {
    pub fn new_h2(h2: H2Finger) -> Self {
        Fingerprint { h2, ..Default::default() }
    }

    pub fn h2(&self) -> &H2Finger { &self.h2 }

    pub fn h2_mut(&mut self) -> &mut H2Finger { &mut self.h2 }

    #[cfg(feature = "quic")]
    pub fn h3(&self) -> &H3Finger { &self.h3 }

    #[cfg(feature = "quic")]
    pub fn h3_mut(&mut self) -> &mut H3Finger { &mut self.h3 }
}
