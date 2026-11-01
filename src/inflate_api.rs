//! The public inflate surface: the streaming `Inflate` type and the one-shot
//! `inflate` / `inflate_raw` / `ungzip` functions.

use crate::utils::flatten_chunks;
use crate::zlib::constants::{
    Z_BUF_ERROR, Z_DATA_ERROR, Z_FINISH, Z_MEM_ERROR, Z_NEED_DICT, Z_OK, Z_STREAM_END,
    Z_STREAM_ERROR,
};
use crate::zlib::gzheader::GzHeader;
use crate::zlib::inflate::{
    inflate as zlib_inflate, inflate_end, inflate_get_header, inflate_init2, inflate_reset,
    inflate_set_dictionary,
};
use crate::zlib::inflate_state::InflateState;
use crate::zlib::messages::message;
use crate::zlib::zstream::ZStream;

/// Options accepted by `Inflate`, with the original's defaults.
#[derive(Debug, Clone)]
pub struct InflateOptions {
    /// Window size. See the zlib manual.
    pub window_bits: i32,
    /// Initial dictionary. See the zlib manual.
    pub dictionary: Vec<u8>,
    /// Size of generated data chunks (64K by default).
    pub chunk_size: usize,
    /// Do raw inflate, rather than passing a negative `window_bits`.
    pub raw: bool,
    /// Whether `window_bits` was set by the caller.
    ///
    /// The original distinguishes an explicit `windowBits: 15` from an absent
    /// one by testing the *options object* rather than the merged defaults, and
    /// adds the auto-detect bits only in the absent case. A struct with
    /// defaults cannot express that, so the flag is carried; `Default` leaves
    /// it false and the builders below set it.
    pub window_bits_set: bool,
}

impl Default for InflateOptions {
    fn default() -> Self {
        InflateOptions {
            window_bits: 15,
            dictionary: Vec::new(),
            chunk_size: 1024 * 64,
            raw: false,
            window_bits_set: false,
        }
    }
}

impl InflateOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn window_bits(mut self, bits: i32) -> Self {
        self.window_bits = bits;
        self.window_bits_set = bits != 0;
        self
    }

    pub fn dictionary(mut self, dict: impl Into<Vec<u8>>) -> Self {
        self.dictionary = dict.into();
        self
    }

    pub fn chunk_size(mut self, n: usize) -> Self {
        self.chunk_size = n;
        self
    }

    pub fn raw(mut self, raw: bool) -> Self {
        self.raw = raw;
        self
    }
}

/// Streaming inflate.
///
/// The original exposes `onStart`, `onData` and `onEnd` as overridable
/// methods. Rust has no inheritance, so the two hooks a caller actually needs
/// are optional fields: `capture_header` replaces the documented `onStart`
/// recipe of attaching a `GZheader`, and the collected chunks remain readable
/// so a caller can consume them incrementally instead of overriding `onData`.
pub struct Inflate {
    options: InflateOptions,

    /// Error code after inflate finishes; `Z_OK` on success.
    pub err: i32,
    /// Error message, when `err` is not `Z_OK`.
    pub msg: String,
    /// True once the compressed stream has ended. A stream may end before the
    /// caller's data does, so further `push` calls are no-ops.
    pub ended: bool,

    started: bool,

    /// Chunks of output data.
    pub chunks: Vec<Vec<u8>>,
    /// Uncompressed result, filled once the last chunk has been pushed.
    pub result: Vec<u8>,

    /// The gzip header, when `capture_header` was requested before the first
    /// push.
    pub header: Option<GzHeader>,
    capture_header: bool,

    strm: ZStream,
    state: InflateState,
}

impl Inflate {
    /// Create an inflator. Returns the zlib status rather than throwing, as
    /// the original's constructor does for bad options.
    pub fn new(options: InflateOptions) -> Result<Self, (i32, String)> {
        let mut opt = options;

        // Force the window size for raw data when it was not set directly,
        // because there is no header to auto-detect from.
        if opt.raw && opt.window_bits >= 0 && opt.window_bits < 16 {
            opt.window_bits = -opt.window_bits;
            if opt.window_bits == 0 {
                opt.window_bits = -15;
            }
        }

        // No windowBits given and not raw: set the gzip/deflate auto-detect
        // flag.
        if opt.window_bits >= 0 && opt.window_bits < 16 && !opt.window_bits_set {
            opt.window_bits += 32;
        }

        // A gzip header carries no window size, so auto-detection only works
        // for deflate; force the maximum when gzip is possible.
        if opt.window_bits > 15 && opt.window_bits < 48 && (opt.window_bits & 15) == 0 {
            opt.window_bits |= 15;
        }

        let mut strm = ZStream::new();
        strm.avail_out = 0;
        let mut state = InflateState::new();

        let mut status = inflate_init2(&mut strm, &mut state, opt.window_bits);
        if status != Z_OK {
            return Err((status, String::from(message(status))));
        }

        if opt.raw && !opt.dictionary.is_empty() {
            status = inflate_set_dictionary(&mut state, &opt.dictionary);
            if status != Z_OK {
                return Err((status, String::from(message(status))));
            }
        }

        Ok(Inflate {
            options: opt,
            err: Z_OK,
            msg: String::new(),
            ended: false,
            started: false,
            chunks: Vec::new(),
            result: Vec::new(),
            header: None,
            capture_header: false,
            strm,
            state,
        })
    }

    /// Ask for the gzip header to be captured into `self.header`.
    ///
    /// Must be called before the first `push`, which is where the original's
    /// `onStart` hook runs `zlibInflateGetHeader`.
    pub fn capture_header(&mut self) {
        self.capture_header = true;
    }

    /// Send input to the inflate pipe, collecting output chunks. Returns true
    /// on success.
    ///
    /// `flush_mode` is not needed for normal operation: the end of stream is
    /// detected automatically. `Z_SYNC_FLUSH` forces all currently available
    /// output to be emitted.
    pub fn push(&mut self, data: &[u8], flush_mode: i32) -> bool {
        let chunk_size = self.options.chunk_size;
        let mut status;

        // Once the stream has ended, further pushes are no-ops. A compressed
        // stream can end before the caller's data does, and the caller cannot
        // know that in advance, so the recorded outcome is reported rather
        // than a blanket false: err/msg/result survive trailing garbage.
        if self.ended {
            return self.err == Z_OK;
        }

        self.strm.input = data.to_vec();
        self.strm.next_in = 0;
        self.strm.avail_in = data.len();

        if !self.started {
            self.started = true;
            if self.capture_header {
                inflate_get_header(&mut self.state, GzHeader::new());
            }
        }

        loop {
            if self.strm.avail_out == 0 {
                self.strm.output = vec![0u8; chunk_size];
                self.strm.next_out = 0;
                self.strm.avail_out = chunk_size;
            }

            status = zlib_inflate(&mut self.strm, &mut self.state, flush_mode);

            if status == Z_NEED_DICT && !self.options.dictionary.is_empty() {
                status = inflate_set_dictionary(&mut self.state, &self.options.dictionary);
                if status == Z_OK {
                    status = zlib_inflate(&mut self.strm, &mut self.state, flush_mode);
                } else if status == Z_DATA_ERROR {
                    status = Z_NEED_DICT;
                }
            }

            // Only gzip defines concatenated members (RFC 1952: a gzip file is
            // "a series of members"). A zlib stream ends after its ADLER32 and
            // a raw stream after its final block, so trailing bytes there are
            // not ours to read. `flags != 0` is what distinguishes a decoded
            // gzip header from an auto-detected zlib one, and a trailing zero
            // byte is padding, since no member can begin with 0.
            while self.strm.avail_in > 0
                && status == Z_STREAM_END
                && self.state.wrap & 2 != 0
                && self.state.flags != 0
                && self.strm.input[self.strm.next_in] != 0
            {
                inflate_reset(&mut self.strm, &mut self.state);
                status = zlib_inflate(&mut self.strm, &mut self.state, flush_mode);
            }

            // Hard errors: leave the stream as-is and finalize with this
            // status.
            if status == Z_STREAM_ERROR
                || status == Z_DATA_ERROR
                || status == Z_NEED_DICT
                || status == Z_MEM_ERROR
            {
                break;
            }

            // The real avail_out, before the counters below reset it.
            let last_avail_out = self.strm.avail_out;

            if self.strm.next_out > 0
                && (self.strm.avail_out == 0 || status == Z_STREAM_END || flush_mode > 0)
            {
                // Flush when the buffer is full, the stream ended, or a flush
                // was requested, to push out the tail as node's zlib does.
                let n = self.strm.next_out;
                self.on_data(self.strm.output[..n].to_vec());

                // Force a fresh output buffer next time round, so the emitted
                // tail is not sent twice.
                self.strm.avail_out = 0;
                self.strm.next_out = 0;
            }

            // A full output buffer means there may be more to produce. With
            // Z_NO_FLUSH that is reported as Z_OK and with Z_FINISH as
            // Z_BUF_ERROR, but both must continue: what matters is only
            // whether the output buffer was exhausted.
            if (status == Z_OK || status == Z_BUF_ERROR) && last_avail_out == 0 {
                continue;
            }

            if status == Z_STREAM_END {
                status = inflate_end(&mut self.state);
                break;
            }

            if self.strm.avail_in == 0 {
                // Input exhausted. If the caller declared the end of the
                // stream but Z_STREAM_END never arrived, the compressed data
                // is truncated; returning the partial output as success would
                // be indistinguishable from a complete decode.
                if flush_mode == Z_FINISH {
                    status = inflate_end(&mut self.state);
                    if status == Z_OK {
                        status = Z_BUF_ERROR;
                    }
                    break;
                }

                // Not the last chunk: the stream is alive and more input may
                // follow. The only non-finalizing exit.
                return true;
            }
        }

        self.err = status;
        self.msg = if self.strm.msg.is_empty() {
            String::from(message(status))
        } else {
            self.strm.msg.clone()
        };
        self.ended = true;
        self.on_end(status);

        status == Z_OK
    }

    fn on_data(&mut self, chunk: Vec<u8>) {
        self.chunks.push(chunk);
    }

    fn on_end(&mut self, status: i32) {
        if status == Z_OK {
            self.result = flatten_chunks(&self.chunks);
        }
        self.chunks = Vec::new();
        self.header = self.state.head.clone();
    }
}

/// One-shot inflate. Auto-detects gzip and zlib via the wrapper header, so
/// `ungzip` is a convenience alias of this function.
pub fn inflate(input: &[u8], options: InflateOptions) -> Result<Vec<u8>, String> {
    let mut inflator = Inflate::new(options).map_err(|(_, msg)| msg)?;
    inflator.push(input, Z_FINISH);
    if inflator.err != Z_OK {
        return Err(inflator.msg);
    }
    Ok(inflator.result)
}

/// The same as `inflate`, but consumes raw data without a wrapper.
pub fn inflate_raw(input: &[u8], options: InflateOptions) -> Result<Vec<u8>, String> {
    inflate(input, options.raw(true))
}

/// An alias of `inflate`, which already auto-detects gzip.
pub fn ungzip(input: &[u8], options: InflateOptions) -> Result<Vec<u8>, String> {
    inflate(input, options)
}
