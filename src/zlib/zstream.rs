// (C) 1995-2013 Jean-loup Gailly and Mark Adler
// (C) 2014-2017 Vitaly Puzrin and Andrey Tupitsin
//
// This software is provided 'as-is', without any express or implied
// warranty. In no event will the authors be held liable for any damages
// arising from the use of this software.
//
// Permission is granted to anyone to use this software for any purpose,
// including commercial applications, and to alter it and redistribute it
// freely, subject to the following restrictions:
//
// 1. The origin of this software must not be misrepresented; you must not
//   claim that you wrote the original software. If you use this software
//   in a product, an acknowledgment in the product documentation would be
//   appreciated but is not required.
// 2. Altered source versions must be plainly marked as such, and must not be
//   misrepresented as being the original software.
// 3. This notice may not be removed or altered from any source distribution.

//! The stream descriptor both halves of zlib read and write.

/// zlib's `z_stream`: the input and output windows plus the cursors into them.
///
/// zlib in C holds `next_in`/`next_out` as moving pointers. The JavaScript
/// original has no pointers, so it keeps a buffer plus an index, and every
/// read is `strm.input[strm.next_in]`. This port keeps that index form: the
/// buffers are owned `Vec<u8>` and the cursors stay plain `usize`, so the
/// arithmetic in `deflate` and `inflate` transliterates line for line.
///
/// `state` is deliberately absent. In C and in JavaScript the compressor
/// state hangs off the stream, and `deflate(strm, flush)` reaches through
/// `strm.state` to find it. Rust cannot borrow the state mutably while also
/// borrowing `strm.output` mutably through the same `&mut strm`, so the state
/// is owned by the caller and passed alongside: `deflate(&mut strm, &mut
/// state, flush)`. The observable behaviour is unchanged; only the internal
/// plumbing differs, and the public `Deflate`/`Inflate` types hide it.
#[derive(Debug, Default, Clone)]
pub struct ZStream {
    /// Input bytes. `next_in` indexes into this.
    pub input: Vec<u8>,
    /// Next input byte.
    pub next_in: usize,
    /// Number of bytes available at input.
    pub avail_in: usize,
    /// Total number of input bytes read so far.
    pub total_in: usize,

    /// Output bytes. `next_out` indexes into this.
    pub output: Vec<u8>,
    /// Next output byte should be put there.
    pub next_out: usize,
    /// Remaining free space at output.
    pub avail_out: usize,
    /// Total number of bytes output so far.
    pub total_out: usize,

    /// Last error message, empty if no error.
    pub msg: String,

    /// Best guess about the data type: binary or text.
    pub data_type: i32,
    /// Adler-32 (or CRC-32, for gzip) of the uncompressed data.
    pub adler: u32,
}

impl ZStream {
    /// A stream with zlib's own initial values.
    ///
    /// `data_type` starts at `Z_UNKNOWN` (2) rather than zero, matching the
    /// original constructor; a port that relied on `Default` alone would
    /// start it at `Z_BINARY` and report the wrong type for empty input.
    pub fn new() -> Self {
        ZStream {
            input: Vec::new(),
            next_in: 0,
            avail_in: 0,
            total_in: 0,
            output: Vec::new(),
            next_out: 0,
            avail_out: 0,
            total_out: 0,
            msg: String::new(),
            data_type: super::constants::Z_UNKNOWN,
            adler: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ZStream;
    use crate::zlib::constants::Z_UNKNOWN;

    #[test]
    fn starts_with_zlibs_own_initial_values() {
        let s = ZStream::new();
        assert_eq!(
            s.data_type, Z_UNKNOWN,
            "data_type must start at Z_UNKNOWN, not 0"
        );
        assert_eq!(s.adler, 0);
        assert_eq!((s.next_in, s.avail_in, s.total_in), (0, 0, 0));
        assert_eq!((s.next_out, s.avail_out, s.total_out), (0, 0, 0));
        assert!(s.msg.is_empty());
    }
}
