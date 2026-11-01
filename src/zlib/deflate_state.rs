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

//! The deflate encoder's state, shared by the LZ77 engine and the tree coder.
//!
//! Split out of `deflate.rs` so `trees.rs` can take `&mut DeflateState` without
//! a circular module dependency, exactly as `inflate_state.rs` does for the
//! decoder.

use super::gzheader::GzHeader;

pub const MAX_MEM_LEVEL: i32 = 9;
pub const MAX_WBITS: i32 = 15;
pub const DEF_MEM_LEVEL: i32 = 8;

pub const LENGTH_CODES: usize = 29;
pub const LITERALS: usize = 256;
pub const L_CODES: usize = LITERALS + 1 + LENGTH_CODES;
pub const D_CODES: usize = 30;
pub const BL_CODES: usize = 19;
pub const HEAP_SIZE: usize = 2 * L_CODES + 1;
pub const MAX_BITS: usize = 15;
pub const BUF_SIZE: usize = 16;

pub const MIN_MATCH: usize = 3;
pub const MAX_MATCH: usize = 258;
pub const MIN_LOOKAHEAD: usize = MAX_MATCH + MIN_MATCH + 1;

pub const PRESET_DICT: i32 = 0x20;

pub const INIT_STATE: i32 = 42; /* zlib header -> BUSY_STATE */
pub const GZIP_STATE: i32 = 57; /* gzip header -> BUSY_STATE | EXTRA_STATE */
pub const EXTRA_STATE: i32 = 69; /* gzip extra block -> NAME_STATE */
pub const NAME_STATE: i32 = 73; /* gzip file name -> COMMENT_STATE */
pub const COMMENT_STATE: i32 = 91; /* gzip comment -> HCRC_STATE */
pub const HCRC_STATE: i32 = 103; /* gzip header CRC -> BUSY_STATE */
pub const BUSY_STATE: i32 = 113; /* deflate -> FINISH_STATE */
pub const FINISH_STATE: i32 = 666; /* stream complete */

pub const BS_NEED_MORE: i32 = 1; /* block not completed, need more input or output */
pub const BS_BLOCK_DONE: i32 = 2; /* block flush performed */
pub const BS_FINISH_STARTED: i32 = 3; /* finish started, need only more output */
pub const BS_FINISH_DONE: i32 = 4; /* finish done, accept no more input or output */

pub const OS_CODE: i32 = 0x03; // Unix. Not detected; this default is always used.

pub const MAX_BL_BITS: usize = 7;
pub const END_BLOCK: usize = 256;
pub const REP_3_6: usize = 16;
pub const REPZ_3_10: usize = 17;
pub const REPZ_11_138: usize = 18;

pub const STORED_BLOCK: i32 = 0;
pub const STATIC_TREES: i32 = 1;
pub const DYN_TREES: i32 = 2;

/* extra bits for each length code */
pub const EXTRA_LBITS: [u8; LENGTH_CODES] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/* extra bits for each distance code */
pub const EXTRA_DBITS: [u8; D_CODES] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/* extra bits for each bit length code */
pub const EXTRA_BLBITS: [u8; BL_CODES] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7];

/// The bit length codes are sent in order of decreasing probability, so the
/// lengths of unused codes need not be transmitted.
pub const BL_ORDER: [u8; BL_CODES] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Which of the three trees a tree operation applies to.
///
/// The original passes a `TreeDesc` object holding a live reference to the
/// dynamic tree array plus its `max_code` and static descriptor. Rust cannot
/// hold that reference while the same state is borrowed mutably, so the tree
/// is named instead and resolved at each use; `max_code` moves into the state
/// as three fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeKind {
    /// Literal and length tree.
    Literal,
    /// Distance tree.
    Distance,
    /// Huffman tree for the bit lengths of the other two.
    BitLength,
}

/// Per-level tuning: `good_length`, `max_lazy`, `nice_length`, `max_chain`.
///
/// The original stores a function pointer per level as a fifth field; the
/// dispatch is a `match` on the level in `deflate.rs` instead, so levels 1..3
/// still take `deflate_fast` and 4..9 `deflate_slow`.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub good_length: u16,
    pub max_lazy: u16,
    pub nice_length: u16,
    pub max_chain: u16,
}

pub const CONFIGURATION_TABLE: [Config; 10] = [
    /*                good  lazy  nice  chain */
    Config {
        good_length: 0,
        max_lazy: 0,
        nice_length: 0,
        max_chain: 0,
    }, /* 0 store only */
    Config {
        good_length: 4,
        max_lazy: 4,
        nice_length: 8,
        max_chain: 4,
    }, /* 1 max speed */
    Config {
        good_length: 4,
        max_lazy: 5,
        nice_length: 16,
        max_chain: 8,
    }, /* 2 */
    Config {
        good_length: 4,
        max_lazy: 6,
        nice_length: 32,
        max_chain: 32,
    }, /* 3 */
    Config {
        good_length: 4,
        max_lazy: 4,
        nice_length: 16,
        max_chain: 16,
    }, /* 4 lazy matches */
    Config {
        good_length: 8,
        max_lazy: 16,
        nice_length: 32,
        max_chain: 32,
    }, /* 5 */
    Config {
        good_length: 8,
        max_lazy: 16,
        nice_length: 128,
        max_chain: 128,
    }, /* 6 */
    Config {
        good_length: 8,
        max_lazy: 32,
        nice_length: 128,
        max_chain: 256,
    }, /* 7 */
    Config {
        good_length: 32,
        max_lazy: 128,
        nice_length: 258,
        max_chain: 1024,
    }, /* 8 */
    Config {
        good_length: 32,
        max_lazy: 258,
        nice_length: 258,
        max_chain: 4096,
    }, /* 9 max */
];

/// zlib's `deflate_state`.
///
/// The interleaved tree arrays are kept exactly as the original lays them out:
/// one flat `u16` array per tree with `Freq` at `i * 2` and `Len` / `Code` /
/// `Dad` sharing the slot at `i * 2 + 1`. zlib unions those three in C, and the
/// phase of tree construction decides which one the slot means; separating them
/// would change the aliasing the algorithm relies on.
#[derive(Debug, Clone)]
pub struct DeflateState {
    pub status: i32,
    /// Output still pending. `sym_buf` indexes into the same buffer.
    pub pending_buf: Vec<u8>,
    pub pending_buf_size: usize,
    /// Next pending byte to output to the stream.
    pub pending_out: usize,
    /// Number of bytes in the pending buffer.
    pub pending: usize,
    /// Bit 0 true for zlib, bit 1 true for gzip.
    pub wrap: i32,
    /// gzip header information to write.
    pub gzhead: Option<GzHeader>,
    /// Where in extra, name, or comment.
    pub gzindex: usize,
    pub method: i32,
    /// Value of the flush param for the previous deflate call.
    pub last_flush: i32,

    pub w_size: usize,
    pub w_bits: i32,
    pub w_mask: usize,

    /// Sliding window. Input bytes are read into the second half and move to
    /// the first half later, keeping a dictionary of at least `w_size` bytes.
    pub window: Vec<u8>,
    pub window_size: usize,

    /// Link to an older string with the same hash index, modulo 32K.
    pub prev: Vec<u16>,
    /// Heads of the hash chains, or NIL.
    pub head: Vec<u16>,

    /// Hash index of the string to be inserted.
    pub ins_h: usize,
    /// Use the classic zlib hash instead of the default ANZAC++ one.
    pub legacy_hash: bool,
    pub hash_size: usize,
    pub hash_bits: usize,
    pub hash_mask: usize,
    /// Bits to shift `ins_h` by per input step, so that after `MIN_MATCH`
    /// steps the oldest byte no longer contributes to the key.
    pub hash_shift: usize,

    /// Window position at the start of the current output block. Goes negative
    /// when the window slides, which is why it is signed.
    pub block_start: isize,

    pub match_length: usize,
    pub prev_match: usize,
    pub match_available: bool,
    pub strstart: usize,
    pub match_start: usize,
    pub lookahead: usize,

    /// Length of the best match at the previous step; matches no longer than
    /// this are discarded by the lazy evaluation.
    pub prev_length: usize,

    pub max_chain_length: usize,
    pub max_lazy_match: usize,

    pub level: i32,
    pub strategy: i32,

    pub good_match: usize,
    pub nice_match: usize,

    /* used by trees.rs */
    pub dyn_ltree: Vec<u16>,
    pub dyn_dtree: Vec<u16>,
    pub bl_tree: Vec<u16>,

    /// Largest code with non-zero frequency, per tree. Replaces the three
    /// `TreeDesc.max_code` fields.
    pub l_max_code: i32,
    pub d_max_code: i32,
    pub bl_max_code: i32,

    /// Number of codes at each bit length for an optimal tree.
    pub bl_count: Vec<u16>,

    /// Heap used to build the Huffman trees. `heap[0]` is unused; the sons of
    /// `heap[n]` are `heap[2n]` and `heap[2n + 1]`.
    pub heap: Vec<u16>,
    pub heap_len: usize,
    pub heap_max: usize,

    /// Depth of each subtree, the tie breaker for equal frequencies.
    pub depth: Vec<u16>,

    /// Offset of the symbol buffer within `pending_buf`.
    pub sym_buf: usize,
    pub lit_bufsize: usize,
    pub sym_next: usize,
    pub sym_end: usize,

    pub opt_len: isize,
    pub static_len: isize,
    pub matches: usize,
    /// Bytes at the end of the window left to insert.
    pub insert: usize,

    /// Bit output buffer; bits are inserted starting at the least significant.
    pub bi_buf: u32,
    pub bi_valid: usize,
}

impl Default for DeflateState {
    fn default() -> Self {
        Self::new()
    }
}

impl DeflateState {
    pub fn new() -> Self {
        DeflateState {
            status: 0,
            pending_buf: Vec::new(),
            pending_buf_size: 0,
            pending_out: 0,
            pending: 0,
            wrap: 0,
            gzhead: None,
            gzindex: 0,
            method: super::constants::Z_DEFLATED,
            last_flush: -1,
            w_size: 0,
            w_bits: 0,
            w_mask: 0,
            window: Vec::new(),
            window_size: 0,
            prev: Vec::new(),
            head: Vec::new(),
            ins_h: 0,
            legacy_hash: false,
            hash_size: 0,
            hash_bits: 0,
            hash_mask: 0,
            hash_shift: 0,
            block_start: 0,
            match_length: 0,
            prev_match: 0,
            match_available: false,
            strstart: 0,
            match_start: 0,
            lookahead: 0,
            prev_length: 0,
            max_chain_length: 0,
            max_lazy_match: 0,
            level: 0,
            strategy: 0,
            good_match: 0,
            nice_match: 0,
            dyn_ltree: vec![0u16; HEAP_SIZE * 2],
            dyn_dtree: vec![0u16; (2 * D_CODES + 1) * 2],
            bl_tree: vec![0u16; (2 * BL_CODES + 1) * 2],
            l_max_code: 0,
            d_max_code: 0,
            bl_max_code: 0,
            bl_count: vec![0u16; MAX_BITS + 1],
            heap: vec![0u16; 2 * L_CODES + 1],
            heap_len: 0,
            heap_max: 0,
            depth: vec![0u16; 2 * L_CODES + 1],
            sym_buf: 0,
            lit_bufsize: 0,
            sym_next: 0,
            sym_end: 0,
            opt_len: 0,
            static_len: 0,
            matches: 0,
            insert: 0,
            bi_buf: 0,
            bi_valid: 0,
        }
    }

    /// The dynamic tree for `kind`.
    pub fn tree(&self, kind: TreeKind) -> &[u16] {
        match kind {
            TreeKind::Literal => &self.dyn_ltree,
            TreeKind::Distance => &self.dyn_dtree,
            TreeKind::BitLength => &self.bl_tree,
        }
    }

    pub fn tree_mut(&mut self, kind: TreeKind) -> &mut [u16] {
        match kind {
            TreeKind::Literal => &mut self.dyn_ltree,
            TreeKind::Distance => &mut self.dyn_dtree,
            TreeKind::BitLength => &mut self.bl_tree,
        }
    }

    pub fn max_code(&self, kind: TreeKind) -> i32 {
        match kind {
            TreeKind::Literal => self.l_max_code,
            TreeKind::Distance => self.d_max_code,
            TreeKind::BitLength => self.bl_max_code,
        }
    }

    pub fn set_max_code(&mut self, kind: TreeKind, v: i32) {
        match kind {
            TreeKind::Literal => self.l_max_code = v,
            TreeKind::Distance => self.d_max_code = v,
            TreeKind::BitLength => self.bl_max_code = v,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_table_matches_zlibs_levels() {
        assert_eq!(CONFIGURATION_TABLE.len(), 10);
        let l0 = CONFIGURATION_TABLE[0];
        assert_eq!(
            (l0.good_length, l0.max_lazy, l0.nice_length, l0.max_chain),
            (0, 0, 0, 0)
        );
        let l6 = CONFIGURATION_TABLE[6];
        assert_eq!(
            (l6.good_length, l6.max_lazy, l6.nice_length, l6.max_chain),
            (8, 16, 128, 128)
        );
        let l9 = CONFIGURATION_TABLE[9];
        assert_eq!(
            (l9.good_length, l9.max_lazy, l9.nice_length, l9.max_chain),
            (32, 258, 258, 4096)
        );
    }

    #[test]
    fn derived_sizes_match_the_original() {
        assert_eq!(L_CODES, 286);
        assert_eq!(HEAP_SIZE, 573);
        assert_eq!(MIN_LOOKAHEAD, 262);
    }

    #[test]
    fn trees_are_sized_for_interleaved_freq_and_len() {
        let s = DeflateState::new();
        assert_eq!(s.dyn_ltree.len(), HEAP_SIZE * 2);
        assert_eq!(s.dyn_dtree.len(), (2 * D_CODES + 1) * 2);
        assert_eq!(s.bl_tree.len(), (2 * BL_CODES + 1) * 2);
        assert!(s.dyn_ltree.iter().all(|&v| v == 0));
    }

    #[test]
    fn tree_selection_round_trips() {
        let mut s = DeflateState::new();
        for kind in [TreeKind::Literal, TreeKind::Distance, TreeKind::BitLength] {
            s.tree_mut(kind)[0] = 7;
            assert_eq!(s.tree(kind)[0], 7);
            s.set_max_code(kind, 42);
            assert_eq!(s.max_code(kind), 42);
        }
    }
}
