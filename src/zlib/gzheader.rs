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

//! The gzip member header, as written by deflate and read back by inflate.

/// zlib's `gz_header`.
///
/// `extra` is `Option<Vec<u8>>` rather than a plain `Vec` because inflate
/// distinguishes "no extra field" from "an extra field of length zero": the
/// original stores `null` for the former, and `inflateGetHeader` only fills
/// the field when the FEXTRA flag is set.
///
/// `extra_len` is kept even though a `Vec` knows its own length. The original
/// comment says it is unnecessary in JavaScript but left "for few code
/// modifications", and inflate still assigns it while parsing; dropping it
/// would mean editing the parse loop, which is exactly the kind of drift that
/// loses bit-exactness.
///
/// The `extra_max`, `name_max` and `comm_max` limits are deliberately absent.
/// zlib needs them because the caller supplies fixed buffers; here the fields
/// grow on demand and inflate caps them at 65536 bytes internally.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GzHeader {
    /// True if compressed data believed to be text.
    pub text: i32,
    /// Modification time.
    pub time: u32,
    /// Extra flags (not used when writing a gzip file).
    pub xflags: i32,
    /// Operating system.
    pub os: i32,
    /// Extra field, or `None` if none.
    pub extra: Option<Vec<u8>>,
    /// Extra field length (valid if `extra` is `Some`).
    pub extra_len: usize,
    /// File name, or `None` if the FNAME flag was not set.
    pub name: Option<String>,
    /// Comment, or `None` if the FCOMMENT flag was not set.
    pub comment: Option<String>,
    /// True if there was or will be a header crc.
    pub hcrc: i32,
    /// True when done reading the gzip header (not used when writing).
    pub done: bool,
}

impl GzHeader {
    /// A header with zlib's own initial values: no extra, no name, no comment.
    pub fn new() -> Self {
        GzHeader::default()
    }
}

#[cfg(test)]
mod tests {
    use super::GzHeader;

    #[test]
    fn distinguishes_absent_extra_from_empty_extra() {
        // inflate must be able to tell "FEXTRA not set" from "FEXTRA set,
        // length 0". A port using Vec::new() for both loses that.
        let absent = GzHeader::new();
        assert!(absent.extra.is_none());

        let mut empty = GzHeader::new();
        empty.extra = Some(Vec::new());
        assert!(empty.extra.is_some());
        assert_ne!(absent, empty);
    }

    #[test]
    fn starts_not_done() {
        assert!(!GzHeader::new().done);
    }
}
