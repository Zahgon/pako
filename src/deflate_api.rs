//! The public deflate surface: the streaming `Deflate` type and the one-shot
//! `deflate` / `deflate_raw` / `gzip` functions.

use crate::utils::flatten_chunks;
use crate::zlib::constants::{
    Z_DEFAULT_COMPRESSION, Z_DEFAULT_STRATEGY, Z_DEFLATED, Z_FINISH, Z_FULL_FLUSH, Z_OK,
    Z_STREAM_END, Z_STREAM_ERROR, Z_SYNC_FLUSH,
};
use crate::zlib::deflate::{
    deflate as zlib_deflate, deflate_end, deflate_init2, deflate_set_dictionary, deflate_set_header,
};
use crate::zlib::deflate_state::{DeflateState, DEF_MEM_LEVEL};
use crate::zlib::gzheader::GzHeader;
use crate::zlib::messages::message;
use crate::zlib::zstream::ZStream;

/// Options accepted by `Deflate`, with the original's defaults.
#[derive(Debug, Clone)]
pub struct DeflateOptions {
    /// Compression level. See the zlib manual.
    pub level: i32,
    /// Size of generated data chunks (16K by default).
    pub chunk_size: usize,
    /// Window size. See the zlib manual.
    pub window_bits: i32,
    /// Memory level. See the zlib manual.
    pub mem_level: i32,
    /// Compression strategy. See the zlib manual.
    pub strategy: i32,
    /// Do raw deflate, rather than passing a negative `window_bits`.
    pub raw: bool,
    /// Create a gzip wrapper.
    pub gzip: bool,
    /// Initial dictionary. See the zlib manual.
    pub dictionary: Vec<u8>,
    /// Use the classic zlib hash, which matches canonical zlib output
    /// byte-for-byte. The default `false` uses the faster ANZAC++ hash, which
    /// matches recent node.js output instead.
    pub legacy_hash: bool,
}

impl Default for DeflateOptions {
    fn default() -> Self {
        DeflateOptions {
            level: Z_DEFAULT_COMPRESSION,
            chunk_size: 16384,
            window_bits: 15,
            mem_level: 8,
            strategy: Z_DEFAULT_STRATEGY,
            raw: false,
            gzip: false,
            dictionary: Vec::new(),
            legacy_hash: false,
        }
    }
}

impl DeflateOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn level(mut self, level: i32) -> Self {
        self.level = level;
        self
    }

    pub fn chunk_size(mut self, n: usize) -> Self {
        self.chunk_size = n;
        self
    }

    pub fn window_bits(mut self, bits: i32) -> Self {
        self.window_bits = bits;
        self
    }

    pub fn mem_level(mut self, n: i32) -> Self {
        self.mem_level = n;
        self
    }

    pub fn strategy(mut self, s: i32) -> Self {
        self.strategy = s;
        self
    }

    pub fn raw(mut self, raw: bool) -> Self {
        self.raw = raw;
        self
    }

    pub fn gzip(mut self, gzip: bool) -> Self {
        self.gzip = gzip;
        self
    }

    pub fn dictionary(mut self, dict: impl Into<Vec<u8>>) -> Self {
        self.dictionary = dict.into();
        self
    }

    pub fn legacy_hash(mut self, legacy: bool) -> Self {
        self.legacy_hash = legacy;
        self
    }
}

/// Streaming deflate.
///
/// As with `Inflate`, the original's overridable `onStart` / `onData` /
/// `onEnd` methods become plain fields and accessors: `set_header` replaces
/// the `onStart` recipe of attaching a `GZheader`, and `chunks` stays readable
/// for a caller that wants the output incrementally.
pub struct Deflate {
    options: DeflateOptions,

    /// Error code after deflate finishes; `Z_OK` on success. Errors are
    /// possible only on bad options.
    pub err: i32,
    /// Error message, when `err` is not `Z_OK`.
    pub msg: String,

    ended: bool,
    started: bool,

    /// Chunks of compressed data.
    pub chunks: Vec<Vec<u8>>,
    /// Compressed result, filled once the last chunk has been pushed.
    pub result: Vec<u8>,

    strm: ZStream,
    state: DeflateState,
}

impl Deflate {
    /// Create a deflator. Returns the zlib status rather than throwing, as the
    /// original's constructor does for bad options.
    pub fn new(options: DeflateOptions) -> Result<Self, (i32, String)> {
        let mut opt = options;

        if opt.raw && opt.window_bits > 0 {
            opt.window_bits = -opt.window_bits;
        } else if opt.gzip && opt.window_bits > 0 && opt.window_bits < 16 {
            opt.window_bits += 16;
        }

        let mut strm = ZStream::new();
        strm.avail_out = 0;
        let mut state = DeflateState::new();

        let mut status = deflate_init2(
            &mut strm,
            &mut state,
            opt.level,
            Z_DEFLATED,
            opt.window_bits,
            opt.mem_level,
            opt.strategy,
            opt.legacy_hash,
        );

        if status != Z_OK {
            return Err((status, String::from(message(status))));
        }

        if !opt.dictionary.is_empty() {
            if opt.gzip {
                return Err((
                    Z_STREAM_ERROR,
                    String::from("dictionary is not supported with gzip"),
                ));
            }

            status = deflate_set_dictionary(&mut strm, &mut state, &opt.dictionary);
            if status != Z_OK {
                return Err((status, String::from(message(status))));
            }
        }

        Ok(Deflate {
            options: opt,
            err: Z_OK,
            msg: String::new(),
            ended: false,
            started: false,
            chunks: Vec::new(),
            result: Vec::new(),
            strm,
            state,
        })
    }

    /// Set the gzip header to write. Must be called before the first `push`.
    pub fn set_header(&mut self, head: GzHeader) -> i32 {
        deflate_set_header(&mut self.state, head)
    }

    /// Send input to the deflate pipe, collecting compressed chunks. Returns
    /// true on success.
    ///
    /// The last block must be pushed with `Z_FINISH`, which flushes the
    /// internal buffers and fills `result`.
    pub fn push(&mut self, data: &[u8], flush_mode: i32) -> bool {
        let chunk_size = self.options.chunk_size;
        let mut status;

        if self.ended {
            return false;
        }

        self.strm.input = data.to_vec();
        self.strm.next_in = 0;
        self.strm.avail_in = data.len();

        if !self.started {
            self.started = true;
        }

        loop {
            if self.strm.avail_out == 0 {
                self.strm.output = vec![0u8; chunk_size];
                self.strm.next_out = 0;
                self.strm.avail_out = chunk_size;
            }

            // Keep avail_out above 6 so a sync or full flush cannot repeat its
            // marker across two calls.
            if (flush_mode == Z_SYNC_FLUSH || flush_mode == Z_FULL_FLUSH)
                && self.strm.avail_out <= 6
            {
                let n = self.strm.next_out;
                self.on_data(self.strm.output[..n].to_vec());
                self.strm.avail_out = 0;
                continue;
            }

            status = zlib_deflate(&mut self.strm, &mut self.state, flush_mode);

            // A hard error, such as an unsupported flush mode: stop rather
            // than loop forever.
            if status == Z_STREAM_ERROR {
                break;
            }

            // Ended: flush the tail and finalize with the deflate_end status.
            if status == Z_STREAM_END {
                if self.strm.next_out > 0 {
                    let n = self.strm.next_out;
                    self.on_data(self.strm.output[..n].to_vec());
                }
                status = deflate_end(&mut self.strm, &mut self.state);
                break;
            }

            if self.strm.avail_out == 0 {
                let out = std::mem::take(&mut self.strm.output);
                self.on_data(out);
                continue;
            }

            if flush_mode > 0 && self.strm.next_out > 0 {
                let n = self.strm.next_out;
                self.on_data(self.strm.output[..n].to_vec());
                self.strm.avail_out = 0;
                continue;
            }

            // Input exhausted but the stream has not ended: the only
            // non-finalizing exit, since more input may follow.
            if self.strm.avail_in == 0 {
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
    }
}

/// Compress `data` with the deflate algorithm and the given options.
pub fn deflate(input: &[u8], options: DeflateOptions) -> Result<Vec<u8>, String> {
    let mut deflator = Deflate::new(options).map_err(|(_, msg)| msg)?;
    deflator.push(input, Z_FINISH);
    if deflator.err != Z_OK {
        return Err(deflator.msg);
    }
    Ok(deflator.result)
}

/// The same as `deflate`, but without a wrapper (no header and no adler32).
pub fn deflate_raw(input: &[u8], options: DeflateOptions) -> Result<Vec<u8>, String> {
    deflate(input, options.raw(true))
}

/// The same as `deflate`, but with a gzip wrapper instead of a zlib one.
pub fn gzip(input: &[u8], options: DeflateOptions) -> Result<Vec<u8>, String> {
    deflate(input, options.gzip(true))
}

/// `deflate_init` with the original's default memory level, for a caller that
/// wants only a level.
pub fn deflate_with_level(input: &[u8], level: i32) -> Result<Vec<u8>, String> {
    deflate(
        input,
        DeflateOptions::new().level(level).mem_level(DEF_MEM_LEVEL),
    )
}
