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

//! The inflate decoder's state: its mode machine, sliding window and tables.
//!
//! Split out of `inflate.rs` so the hot decode loop in `inffast.rs` can take
//! `&mut InflateState` without a circular module dependency.

use std::sync::OnceLock;

use super::gzheader::GzHeader;
use super::inftrees::{inflate_table, CodeType};

/* STATES ====================================================================*/

pub const HEAD: i32 = 16180; /* i: waiting for magic header */
pub const FLAGS: i32 = 16181; /* i: waiting for method and flags (gzip) */
pub const TIME: i32 = 16182; /* i: waiting for modification time (gzip) */
pub const OS: i32 = 16183; /* i: waiting for extra flags and operating system (gzip) */
pub const EXLEN: i32 = 16184; /* i: waiting for extra length (gzip) */
pub const EXTRA: i32 = 16185; /* i: waiting for extra bytes (gzip) */
pub const NAME: i32 = 16186; /* i: waiting for end of file name (gzip) */
pub const COMMENT: i32 = 16187; /* i: waiting for end of comment (gzip) */
pub const HCRC: i32 = 16188; /* i: waiting for header crc (gzip) */
pub const DICTID: i32 = 16189; /* i: waiting for dictionary check value */
pub const DICT: i32 = 16190; /* waiting for inflateSetDictionary() call */
pub const TYPE: i32 = 16191; /* i: waiting for type bits, including last-flag bit */
pub const TYPEDO: i32 = 16192; /* i: same, but skip check to exit inflate on new block */
pub const STORED: i32 = 16193; /* i: waiting for stored size (length and complement) */
pub const COPY_: i32 = 16194; /* i/o: same as COPY below, but only first time in */
pub const COPY: i32 = 16195; /* i/o: waiting for input or output to copy stored block */
pub const TABLE: i32 = 16196; /* i: waiting for dynamic block table lengths */
pub const LENLENS: i32 = 16197; /* i: waiting for code length code lengths */
pub const CODELENS: i32 = 16198; /* i: waiting for length/lit and distance code lengths */
pub const LEN_: i32 = 16199; /* i: same as LEN below, but only first time in */
pub const LEN: i32 = 16200; /* i: waiting for length/lit/eob code */
pub const LENEXT: i32 = 16201; /* i: waiting for length extra bits */
pub const DIST: i32 = 16202; /* i: waiting for distance code */
pub const DISTEXT: i32 = 16203; /* i: waiting for distance extra bits */
pub const MATCH: i32 = 16204; /* o: waiting for output space to copy string */
pub const LIT: i32 = 16205; /* o: waiting for output space to write literal */
pub const CHECK: i32 = 16206; /* i: waiting for 32-bit check value */
pub const LENGTH: i32 = 16207; /* i: waiting for 32-bit length (gzip) */
pub const DONE: i32 = 16208; /* finished check, done -- remain here until reset */
pub const BAD: i32 = 16209; /* got a data error -- remain here until reset */
pub const MEM: i32 = 16210; /* got an inflate() memory error -- remain here until reset */
pub const SYNC: i32 = 16211; /* looking for synchronization bytes to restart inflate */

pub const ENOUGH_LENS: usize = 852;
pub const ENOUGH_DISTS: usize = 592;

pub const MAX_WBITS: i32 = 15;
/* 32K LZ77 window */
pub const DEF_WBITS: i32 = MAX_WBITS;

/// Byte-swap a 32-bit value, as the zlib dictionary id check requires.
pub fn zswap32(q: u32) -> u32 {
    ((q >> 24) & 0xff)
        .wrapping_add((q >> 8) & 0xff00)
        .wrapping_add((q & 0xff00) << 8)
        .wrapping_add((q & 0xff) << 24)
}

/// Which pair of decode tables the decoder is currently reading from.
///
/// In C and in JavaScript `state.lencode` is a pointer, reseated between the
/// shared fixed tables and the per-block dynamic ones. Rust cannot hold that
/// pointer alongside `&mut state`, so the selection is named instead and
/// `lencode()` / `distcode()` resolve it. Table *writes* always target the
/// dynamic buffers, which is what the original does too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tables {
    Fixed,
    Dynamic,
}

struct FixedTables {
    lenfix: Vec<i32>,
    distfix: Vec<i32>,
}

static FIXED: OnceLock<FixedTables> = OnceLock::new();

/// The fixed literal/length and distance tables, built once.
///
/// Replaces the original's module-level `virgin` flag and mutable `lenfix` /
/// `distfix`; `OnceLock` gives the same build-once behaviour without the
/// shared mutable state.
fn fixed_tables() -> &'static FixedTables {
    FIXED.get_or_init(|| {
        let mut lens = [0u16; 320];
        let mut work = [0u16; 288];

        /* literal/length table */
        let mut sym = 0;
        while sym < 144 {
            lens[sym] = 8;
            sym += 1;
        }
        while sym < 256 {
            lens[sym] = 9;
            sym += 1;
        }
        while sym < 280 {
            lens[sym] = 7;
            sym += 1;
        }
        while sym < 288 {
            lens[sym] = 8;
            sym += 1;
        }

        let mut lenfix = vec![0i32; 512];
        let mut bits = 9usize;
        inflate_table(
            CodeType::Lens,
            &lens,
            0,
            288,
            &mut lenfix,
            &mut work,
            &mut bits,
        );

        /* distance table */
        let mut sym = 0;
        while sym < 32 {
            lens[sym] = 5;
            sym += 1;
        }

        let mut distfix = vec![0i32; 32];
        let mut bits = 5usize;
        inflate_table(
            CodeType::Dists,
            &lens,
            0,
            32,
            &mut distfix,
            &mut work,
            &mut bits,
        );

        FixedTables { lenfix, distfix }
    })
}

/// The fixed literal/length table, for a caller that cannot hold a borrow of
/// the state at the same time (see `inffast`).
pub fn fixed_lenfix() -> &'static [i32] {
    &fixed_tables().lenfix
}

/// The fixed distance table. Companion to `fixed_lenfix`.
pub fn fixed_distfix() -> &'static [i32] {
    &fixed_tables().distfix
}

/// zlib's `inflate_state`.
#[derive(Debug, Clone)]
pub struct InflateState {
    /// Current inflate mode, one of the `HEAD`..`SYNC` constants.
    pub mode: i32,
    /// True if processing last block.
    pub last: bool,
    /// Bit 0 true for zlib, bit 1 true for gzip, bit 2 true to validate check value.
    pub wrap: i32,
    /// True if dictionary provided.
    pub havedict: bool,
    /// gzip header method and flags (0 if zlib), or -1 if raw or no header yet.
    pub flags: i32,
    /// zlib header max distance (INFLATE_STRICT).
    pub dmax: usize,
    /// Protected copy of check value.
    pub check: u32,
    /// Protected copy of output count.
    pub total: usize,
    /// Where to save gzip header information.
    pub head: Option<GzHeader>,

    /* sliding window */
    /// Log base 2 of requested window size.
    pub wbits: i32,
    /// Window size or zero if not using window.
    pub wsize: usize,
    /// Valid bytes in the window.
    pub whave: usize,
    /// Window write index.
    pub wnext: usize,
    /// Allocated sliding window, if needed.
    pub window: Vec<u8>,

    /* bit accumulator */
    /// Input bit accumulator.
    pub hold: u32,
    /// Number of bits in `hold`.
    pub bits: usize,

    /* for string and stored block copying */
    /// Literal or length of data to copy.
    pub length: usize,
    /// Distance back to copy string from.
    pub offset: usize,

    /* for table and code decoding */
    /// Extra bits needed.
    pub extra: usize,

    /* fixed and dynamic code tables */
    /// Which table pair `lencode()` and `distcode()` resolve to.
    pub active: Tables,
    /// Index bits for the length table.
    pub lenbits: usize,
    /// Index bits for the distance table.
    pub distbits: usize,

    /* dynamic table building */
    /// Number of code length code lengths.
    pub ncode: usize,
    /// Number of length code lengths.
    pub nlen: usize,
    /// Number of distance code lengths.
    pub ndist: usize,
    /// Number of code lengths in `lens`.
    pub have: usize,

    /// Temporary storage for code lengths.
    pub lens: [u16; 320],
    /// Work area for code table building.
    pub work: [u16; 288],

    /// Dynamic table for length/literal codes.
    pub lendyn: Vec<i32>,
    /// Dynamic table for distance codes.
    pub distdyn: Vec<i32>,

    /// If false, allow invalid distance too far.
    pub sane: bool,
    /// Bits back of last unprocessed length/literal.
    pub back: i32,
    /// Initial length of match.
    pub was: usize,
}

impl Default for InflateState {
    fn default() -> Self {
        Self::new()
    }
}

impl InflateState {
    pub fn new() -> Self {
        InflateState {
            mode: 0,
            last: false,
            wrap: 0,
            havedict: false,
            flags: 0,
            dmax: 0,
            check: 0,
            total: 0,
            head: None,
            wbits: 0,
            wsize: 0,
            whave: 0,
            wnext: 0,
            window: Vec::new(),
            hold: 0,
            bits: 0,
            length: 0,
            offset: 0,
            extra: 0,
            active: Tables::Dynamic,
            lenbits: 0,
            distbits: 0,
            ncode: 0,
            nlen: 0,
            ndist: 0,
            have: 0,
            lens: [0; 320],
            work: [0; 288],
            lendyn: Vec::new(),
            distdyn: Vec::new(),
            sane: false,
            back: 0,
            was: 0,
        }
    }

    /// The active length/literal decode table.
    pub fn lencode(&self) -> &[i32] {
        match self.active {
            Tables::Fixed => &fixed_tables().lenfix,
            Tables::Dynamic => &self.lendyn,
        }
    }

    /// The active distance decode table.
    pub fn distcode(&self) -> &[i32] {
        match self.active {
            Tables::Fixed => &fixed_tables().distfix,
            Tables::Dynamic => &self.distdyn,
        }
    }

    /// Point the decoder at the fixed tables, as a stored or fixed-Huffman
    /// block requires.
    pub fn use_fixed_tables(&mut self) {
        fixed_tables();
        self.active = Tables::Fixed;
        self.lenbits = 9;
        self.distbits = 5;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zlib::crc32::crc32;

    fn sig(table: &[i32]) -> String {
        let mut bytes = Vec::with_capacity(table.len() * 4);
        for &v in table {
            bytes.extend_from_slice(&(v as u32).to_le_bytes());
        }
        format!("{:08X}", crc32(0, &bytes, bytes.len(), 0))
    }

    #[test]
    fn fixed_tables_match_the_oracle() {
        // The same whole-table checksums the inftrees tests assert, reached
        // through the lazily built statics rather than a direct call, so a
        // wrong symbol-length loop here is caught too.
        let f = fixed_tables();
        assert_eq!(sig(&f.lenfix), "26385EE9");
        assert_eq!(sig(&f.distfix), "5E4AA16B");
    }

    #[test]
    fn fixed_tables_are_built_once() {
        let a = fixed_tables();
        let b = fixed_tables();
        assert!(std::ptr::eq(a, b));
    }

    #[test]
    fn use_fixed_tables_sets_zlibs_root_sizes() {
        let mut s = InflateState::new();
        s.use_fixed_tables();
        assert_eq!((s.lenbits, s.distbits), (9, 5));
        assert_eq!(s.lencode().len(), 512);
        assert_eq!(s.distcode().len(), 32);
    }

    #[test]
    fn dynamic_is_the_default_selection() {
        let s = InflateState::new();
        assert_eq!(s.active, Tables::Dynamic);
    }

    #[test]
    fn zswap32_reverses_byte_order() {
        assert_eq!(zswap32(0x1234_5678), 0x7856_3412);
        assert_eq!(zswap32(0x0000_0001), 0x0100_0000);
        assert_eq!(zswap32(0xFFFF_FFFF), 0xFFFF_FFFF);
    }
}
