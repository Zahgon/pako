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

//! Huffman tree construction and the bit-level block writer.

use std::sync::OnceLock;

use super::constants::{Z_BINARY, Z_FIXED, Z_TEXT, Z_UNKNOWN};
use super::deflate_state::{
    DeflateState, TreeKind, BL_CODES, BL_ORDER, BUF_SIZE, DYN_TREES, D_CODES, END_BLOCK,
    EXTRA_BLBITS, EXTRA_DBITS, EXTRA_LBITS, HEAP_SIZE, LENGTH_CODES, LITERALS, L_CODES, MAX_BITS,
    MAX_BL_BITS, MAX_MATCH, MIN_MATCH, REPZ_11_138, REPZ_3_10, REP_3_6, STATIC_TREES, STORED_BLOCK,
};

const DIST_CODE_LEN: usize = 512;

/// The tables `tr_static_init` fills in once per process.
struct StaticTables {
    /// The static literal tree. Codes 286 and 287 do not exist but are needed
    /// to build a canonical tree, hence `L_CODES + 2`.
    static_ltree: Vec<u16>,
    /// The static distance tree, trivial: every code is 5 bits.
    static_dtree: Vec<u16>,
    /// First 256 entries map distances 3..258, the rest the top 8 bits of a
    /// 15-bit distance.
    dist_code: Vec<u8>,
    length_code: Vec<u8>,
    base_length: Vec<u16>,
    base_dist: Vec<u16>,
}

static STATIC: OnceLock<StaticTables> = OnceLock::new();

/// Per-tree static descriptor: zlib's `static_tree_desc`.
struct StaticDesc {
    static_tree: &'static [u16],
    extra_bits: &'static [u8],
    extra_base: usize,
    elems: usize,
    max_length: usize,
}

impl StaticDesc {
    fn has_stree(&self) -> bool {
        !self.static_tree.is_empty()
    }
}

fn static_tables() -> &'static StaticTables {
    STATIC.get_or_init(tr_static_init)
}

fn static_desc(kind: TreeKind) -> StaticDesc {
    let t = static_tables();
    match kind {
        TreeKind::Literal => StaticDesc {
            static_tree: &t.static_ltree,
            extra_bits: &EXTRA_LBITS,
            extra_base: LITERALS + 1,
            elems: L_CODES,
            max_length: MAX_BITS,
        },
        TreeKind::Distance => StaticDesc {
            static_tree: &t.static_dtree,
            extra_bits: &EXTRA_DBITS,
            extra_base: 0,
            elems: D_CODES,
            max_length: MAX_BITS,
        },
        TreeKind::BitLength => StaticDesc {
            static_tree: &[],
            extra_bits: &EXTRA_BLBITS,
            extra_base: 0,
            elems: BL_CODES,
            max_length: MAX_BL_BITS,
        },
    }
}

/// Map a match distance to its distance code.
fn d_code(dist: usize) -> usize {
    let t = static_tables();
    if dist < 256 {
        t.dist_code[dist] as usize
    } else {
        t.dist_code[256 + (dist >> 7)] as usize
    }
}

/// Output a short, least significant byte first.
fn put_short(s: &mut DeflateState, w: u32) {
    s.pending_buf[s.pending] = (w & 0xff) as u8;
    s.pending += 1;
    s.pending_buf[s.pending] = ((w >> 8) & 0xff) as u8;
    s.pending += 1;
}

/// Send `value` on `length` bits, least significant bit first.
///
/// `bi_buf` is masked to 16 bits at every step because the original holds it
/// in a `ush`; a port that let the accumulator keep its high bits emits the
/// same bytes until the buffer spills and then diverges.
fn send_bits(s: &mut DeflateState, value: u32, length: usize) {
    if s.bi_valid > BUF_SIZE - length {
        s.bi_buf |= (value << s.bi_valid) & 0xffff;
        let buf = s.bi_buf;
        put_short(s, buf);
        s.bi_buf = value >> (BUF_SIZE - s.bi_valid);
        // `length - BUF_SIZE` alone is negative for any length < 16; this
        // branch is reached only when bi_valid > BUF_SIZE - length, so the
        // three-term sum is positive.
        s.bi_valid = s.bi_valid + length - BUF_SIZE;
    } else {
        s.bi_buf |= (value << s.bi_valid) & 0xffff;
        s.bi_valid += length;
    }
}

fn send_code(s: &mut DeflateState, c: usize, tree: &[u16]) {
    send_bits(s, tree[c * 2] as u32, tree[c * 2 + 1] as usize);
}

/// Reverse the first `len` bits of `code`.
fn bi_reverse(code: u32, len: usize) -> u32 {
    let mut res = 0u32;
    let mut code = code;
    let mut len = len;
    loop {
        res |= code & 1;
        code >>= 1;
        res <<= 1;
        len -= 1;
        if len == 0 {
            break;
        }
    }
    res >> 1
}

/// Flush the bit buffer, keeping at most 7 bits in it.
fn bi_flush(s: &mut DeflateState) {
    if s.bi_valid == 16 {
        let buf = s.bi_buf;
        put_short(s, buf);
        s.bi_buf = 0;
        s.bi_valid = 0;
    } else if s.bi_valid >= 8 {
        s.pending_buf[s.pending] = (s.bi_buf & 0xff) as u8;
        s.pending += 1;
        s.bi_buf >>= 8;
        s.bi_valid -= 8;
    }
}

/// Flush the bit buffer and align the output on a byte boundary.
fn bi_windup(s: &mut DeflateState) {
    if s.bi_valid > 8 {
        let buf = s.bi_buf;
        put_short(s, buf);
    } else if s.bi_valid > 0 {
        s.pending_buf[s.pending] = (s.bi_buf & 0xff) as u8;
        s.pending += 1;
    }
    s.bi_buf = 0;
    s.bi_valid = 0;
}

/// Compute the optimal bit lengths for a tree and update the block's total.
fn gen_bitlen(s: &mut DeflateState, kind: TreeKind) {
    let desc = static_desc(kind);
    let max_code = s.max_code(kind);
    let mut tree = std::mem::take(match kind {
        TreeKind::Literal => &mut s.dyn_ltree,
        TreeKind::Distance => &mut s.dyn_dtree,
        TreeKind::BitLength => &mut s.bl_tree,
    });

    let mut overflow: i32 = 0;

    for bits in 0..=MAX_BITS {
        s.bl_count[bits] = 0;
    }

    /* In a first pass, compute the optimal bit lengths (which may overflow
     * in the case of the bit length tree). */
    tree[s.heap[s.heap_max] as usize * 2 + 1] = 0; /* root of the heap */

    for h in s.heap_max + 1..HEAP_SIZE {
        let n = s.heap[h] as usize;
        let mut bits = tree[tree[n * 2 + 1] as usize * 2 + 1] as usize + 1;
        if bits > desc.max_length {
            bits = desc.max_length;
            overflow += 1;
        }
        /* We overwrite tree[n].Dad which is no longer needed */
        tree[n * 2 + 1] = bits as u16;

        if n as i32 > max_code {
            continue; /* not a leaf node */
        }

        s.bl_count[bits] += 1;
        let mut xbits = 0usize;
        if n >= desc.extra_base {
            xbits = desc.extra_bits[n - desc.extra_base] as usize;
        }
        let f = tree[n * 2] as usize;
        s.opt_len += (f * (bits + xbits)) as isize;
        if desc.has_stree() {
            s.static_len += (f * (desc.static_tree[n * 2 + 1] as usize + xbits)) as isize;
        }
    }

    if overflow == 0 {
        match kind {
            TreeKind::Literal => s.dyn_ltree = tree,
            TreeKind::Distance => s.dyn_dtree = tree,
            TreeKind::BitLength => s.bl_tree = tree,
        }
        return;
    }

    /* Find the first bit length which could increase. */
    loop {
        let mut bits = desc.max_length - 1;
        while s.bl_count[bits] == 0 {
            bits -= 1;
        }
        s.bl_count[bits] -= 1; /* move one leaf down the tree */
        s.bl_count[bits + 1] += 2; /* move one overflow item as its brother */
        s.bl_count[desc.max_length] -= 1;
        /* The brother of the overflow item also moves one step up, but that
         * does not affect bl_count[max_length]. */
        overflow -= 2;
        if overflow <= 0 {
            break;
        }
    }

    /* Recompute all bit lengths, scanning in increasing frequency. It is
     * simpler to reconstruct all lengths than to fix only the wrong ones. */
    let mut h = HEAP_SIZE;
    let mut bits = desc.max_length;
    while bits != 0 {
        let mut n = s.bl_count[bits];
        while n != 0 {
            h -= 1;
            let m = s.heap[h] as usize;
            if m as i32 > max_code {
                continue;
            }
            if tree[m * 2 + 1] as usize != bits {
                s.opt_len += (bits as isize - tree[m * 2 + 1] as isize) * tree[m * 2] as isize;
                tree[m * 2 + 1] = bits as u16;
            }
            n -= 1;
        }
        bits -= 1;
    }

    match kind {
        TreeKind::Literal => s.dyn_ltree = tree,
        TreeKind::Distance => s.dyn_dtree = tree,
        TreeKind::BitLength => s.bl_tree = tree,
    }
}

/// Generate the codes for a tree given the bit counts, which need not be
/// optimal.
fn gen_codes(tree: &mut [u16], max_code: i32, bl_count: &[u16]) {
    let mut next_code = [0u32; MAX_BITS + 1];
    let mut code = 0u32;

    /* The distribution counts generate the code values without bit reversal. */
    for bits in 1..=MAX_BITS {
        code = (code + bl_count[bits - 1] as u32) << 1;
        next_code[bits] = code;
    }

    for n in 0..=max_code.max(-1) {
        let n = n as usize;
        let len = tree[n * 2 + 1] as usize;
        if len == 0 {
            continue;
        }
        /* Now reverse the bits */
        tree[n * 2] = bi_reverse(next_code[len], len) as u16;
        next_code[len] += 1;
    }
}

/// Initialize the various 'constant' tables.
fn tr_static_init() -> StaticTables {
    let mut static_ltree = vec![0u16; (L_CODES + 2) * 2];
    let mut static_dtree = vec![0u16; D_CODES * 2];
    let mut dist_code = vec![0u8; DIST_CODE_LEN];
    let mut length_code = vec![0u8; MAX_MATCH - MIN_MATCH + 1];
    let mut base_length = vec![0u16; LENGTH_CODES];
    let mut base_dist = vec![0u16; D_CODES];
    let mut bl_count = [0u16; MAX_BITS + 1];

    /* Initialize the mapping length (0..255) -> length code (0..28) */
    let mut length = 0usize;
    let mut code = 0usize;
    while code < LENGTH_CODES - 1 {
        base_length[code] = length as u16;
        for _ in 0..(1usize << EXTRA_LBITS[code]) {
            length_code[length] = code as u8;
            length += 1;
        }
        code += 1;
    }
    /* Length 255 (match length 258) can be coded two ways: code 284 plus 5
     * extra bits, or code 285. Overwrite the last entry to pick the shorter. */
    length_code[length - 1] = code as u8;

    /* Initialize the mapping dist (0..32K) -> dist code (0..29) */
    let mut dist = 0usize;
    let mut code = 0usize;
    while code < 16 {
        base_dist[code] = dist as u16;
        for _ in 0..(1usize << EXTRA_DBITS[code]) {
            dist_code[dist] = code as u8;
            dist += 1;
        }
        code += 1;
    }
    dist >>= 7; /* from now on, all distances are divided by 128 */
    while code < D_CODES {
        base_dist[code] = (dist << 7) as u16;
        for _ in 0..(1usize << (EXTRA_DBITS[code] - 7)) {
            dist_code[256 + dist] = code as u8;
            dist += 1;
        }
        code += 1;
    }

    /* Construct the codes of the static literal tree */
    let mut n = 0usize;
    while n <= 143 {
        static_ltree[n * 2 + 1] = 8;
        n += 1;
        bl_count[8] += 1;
    }
    while n <= 255 {
        static_ltree[n * 2 + 1] = 9;
        n += 1;
        bl_count[9] += 1;
    }
    while n <= 279 {
        static_ltree[n * 2 + 1] = 7;
        n += 1;
        bl_count[7] += 1;
    }
    while n <= 287 {
        static_ltree[n * 2 + 1] = 8;
        n += 1;
        bl_count[8] += 1;
    }
    /* Codes 286 and 287 do not exist, but must be included in the tree
     * construction to get a canonical Huffman tree (longest code all ones). */
    gen_codes(&mut static_ltree, (L_CODES + 1) as i32, &bl_count);

    /* The static distance tree is trivial */
    for n in 0..D_CODES {
        static_dtree[n * 2 + 1] = 5;
        static_dtree[n * 2] = bi_reverse(n as u32, 5) as u16;
    }

    StaticTables {
        static_ltree,
        static_dtree,
        dist_code,
        length_code,
        base_length,
        base_dist,
    }
}

/// Initialize a new block.
fn init_block(s: &mut DeflateState) {
    for n in 0..L_CODES {
        s.dyn_ltree[n * 2] = 0;
    }
    for n in 0..D_CODES {
        s.dyn_dtree[n * 2] = 0;
    }
    for n in 0..BL_CODES {
        s.bl_tree[n * 2] = 0;
    }

    s.dyn_ltree[END_BLOCK * 2] = 1;
    s.opt_len = 0;
    s.static_len = 0;
    s.sym_next = 0;
    s.matches = 0;
}

/// Compare two subtrees, using the tree depth as tie breaker when the
/// frequencies are equal. This minimizes the worst case length.
fn smaller(tree: &[u16], n: usize, m: usize, depth: &[u16]) -> bool {
    let n2 = n * 2;
    let m2 = m * 2;
    tree[n2] < tree[m2] || (tree[n2] == tree[m2] && depth[n] <= depth[m])
}

/// Restore the heap property by moving node `k` down.
fn pqdownheap(s: &mut DeflateState, tree: &[u16], k: usize) {
    let v = s.heap[k];
    let mut k = k;
    let mut j = k << 1; /* left son of k */
    while j <= s.heap_len {
        /* Set j to the smallest of the two sons */
        if j < s.heap_len && smaller(tree, s.heap[j + 1] as usize, s.heap[j] as usize, &s.depth) {
            j += 1;
        }
        /* Exit if v is smaller than both sons */
        if smaller(tree, v as usize, s.heap[j] as usize, &s.depth) {
            break;
        }

        /* Exchange v with the smallest son */
        s.heap[k] = s.heap[j];
        k = j;

        /* And continue down the tree, setting j to the left son of k */
        j <<= 1;
    }
    s.heap[k] = v;
}

/// Send the block data compressed using the given Huffman trees.
fn compress_block(s: &mut DeflateState, ltree: &[u16], dtree: &[u16]) {
    let t = static_tables();

    if s.sym_next != 0 {
        let mut sx = 0usize;
        loop {
            let mut dist = s.pending_buf[s.sym_buf + sx] as usize & 0xff;
            sx += 1;
            dist += (s.pending_buf[s.sym_buf + sx] as usize & 0xff) << 8;
            sx += 1;
            let mut lc = s.pending_buf[s.sym_buf + sx] as usize;
            sx += 1;

            if dist == 0 {
                send_code(s, lc, ltree); /* send a literal byte */
            } else {
                /* Here lc is the match length - MIN_MATCH */
                let code = t.length_code[lc] as usize;
                send_code(s, code + LITERALS + 1, ltree); /* the length code */
                let extra = EXTRA_LBITS[code] as usize;
                if extra != 0 {
                    lc -= t.base_length[code] as usize;
                    send_bits(s, lc as u32, extra); /* extra length bits */
                }
                dist -= 1; /* dist is now the match distance - 1 */
                let code = d_code(dist);

                send_code(s, code, dtree); /* send the distance code */
                let extra = EXTRA_DBITS[code] as usize;
                if extra != 0 {
                    dist -= t.base_dist[code] as usize;
                    send_bits(s, dist as u32, extra); /* extra distance bits */
                }
            }

            if sx >= s.sym_next {
                break;
            }
        }
    }

    send_code(s, END_BLOCK, ltree);
}

/// Construct one Huffman tree and assign the code bit strings and lengths.
fn build_tree(s: &mut DeflateState, kind: TreeKind) {
    let desc = static_desc(kind);
    let elems = desc.elems;
    let has_stree = desc.has_stree();

    let mut tree = std::mem::take(match kind {
        TreeKind::Literal => &mut s.dyn_ltree,
        TreeKind::Distance => &mut s.dyn_dtree,
        TreeKind::BitLength => &mut s.bl_tree,
    });

    let mut max_code: i32 = -1;

    /* Construct the initial heap, with the least frequent element in heap[1].
     * The sons of heap[n] are heap[2n] and heap[2n+1]; heap[0] is not used. */
    s.heap_len = 0;
    s.heap_max = HEAP_SIZE;

    for n in 0..elems {
        if tree[n * 2] != 0 {
            s.heap_len += 1;
            s.heap[s.heap_len] = n as u16;
            max_code = n as i32;
            s.depth[n] = 0;
        } else {
            tree[n * 2 + 1] = 0;
        }
    }

    /* The pkzip format requires at least one distance code to exist, and at
     * least one bit to be sent even when there is only one possible code, so
     * force at least two codes of non-zero frequency. */
    while s.heap_len < 2 {
        s.heap_len += 1;
        let node = if max_code < 2 {
            max_code += 1;
            max_code as usize
        } else {
            0
        };
        s.heap[s.heap_len] = node as u16;
        tree[node * 2] = 1;
        s.depth[node] = 0;
        s.opt_len -= 1;

        if has_stree {
            s.static_len -= desc.static_tree[node * 2 + 1] as isize;
        }
        /* node is 0 or 1 so it has no extra bits */
    }
    s.set_max_code(kind, max_code);

    /* The elements heap[heap_len/2+1 .. heap_len] are leaves; establish
     * sub-heaps of increasing lengths. */
    let mut n = s.heap_len >> 1;
    while n >= 1 {
        pqdownheap(s, &tree, n);
        n -= 1;
    }

    /* Construct the Huffman tree by repeatedly combining the two least
     * frequent nodes. */
    let mut node = elems;
    loop {
        /* pqremove: n = node of least frequency */
        let n = s.heap[1] as usize;
        s.heap[1] = s.heap[s.heap_len];
        s.heap_len -= 1;
        pqdownheap(s, &tree, 1);

        let m = s.heap[1] as usize; /* m = node of next least frequency */

        s.heap_max -= 1;
        s.heap[s.heap_max] = n as u16; /* keep the nodes sorted by frequency */
        s.heap_max -= 1;
        s.heap[s.heap_max] = m as u16;

        /* Create a new node, father of n and m */
        tree[node * 2] = tree[n * 2] + tree[m * 2];
        s.depth[node] = if s.depth[n] >= s.depth[m] {
            s.depth[n]
        } else {
            s.depth[m]
        } + 1;
        tree[n * 2 + 1] = node as u16;
        tree[m * 2 + 1] = node as u16;

        /* and insert the new node in the heap */
        s.heap[1] = node as u16;
        node += 1;
        pqdownheap(s, &tree, 1);

        if s.heap_len < 2 {
            break;
        }
    }

    s.heap_max -= 1;
    s.heap[s.heap_max] = s.heap[1];

    match kind {
        TreeKind::Literal => s.dyn_ltree = tree,
        TreeKind::Distance => s.dyn_dtree = tree,
        TreeKind::BitLength => s.bl_tree = tree,
    }

    /* The fields freq and dad are set; generate the bit lengths. */
    gen_bitlen(s, kind);

    /* The field len is now set, so generate the bit codes. */
    let mut tree = std::mem::take(match kind {
        TreeKind::Literal => &mut s.dyn_ltree,
        TreeKind::Distance => &mut s.dyn_dtree,
        TreeKind::BitLength => &mut s.bl_tree,
    });
    gen_codes(&mut tree, max_code, &s.bl_count);
    match kind {
        TreeKind::Literal => s.dyn_ltree = tree,
        TreeKind::Distance => s.dyn_dtree = tree,
        TreeKind::BitLength => s.bl_tree = tree,
    }
}

/// Scan a literal or distance tree to determine the frequencies of the codes
/// in the bit length tree.
fn scan_tree(s: &mut DeflateState, kind: TreeKind) {
    let max_code = s.max_code(kind);
    let mut tree = std::mem::take(match kind {
        TreeKind::Literal => &mut s.dyn_ltree,
        TreeKind::Distance => &mut s.dyn_dtree,
        TreeKind::BitLength => &mut s.bl_tree,
    });

    let mut prevlen: i32 = -1;
    let mut nextlen = tree[1] as usize;
    let mut count = 0usize;
    let mut max_count = 7usize;
    let mut min_count = 4usize;

    if nextlen == 0 {
        max_count = 138;
        min_count = 3;
    }
    tree[(max_code + 1) as usize * 2 + 1] = 0xffff; /* guard */

    for n in 0..=max_code.max(-1) {
        let n = n as usize;
        let curlen = nextlen;
        nextlen = tree[(n + 1) * 2 + 1] as usize;

        count += 1;
        if count < max_count && curlen == nextlen {
            continue;
        } else if count < min_count {
            s.bl_tree[curlen * 2] += count as u16;
        } else if curlen != 0 {
            if curlen as i32 != prevlen {
                s.bl_tree[curlen * 2] += 1;
            }
            s.bl_tree[REP_3_6 * 2] += 1;
        } else if count <= 10 {
            s.bl_tree[REPZ_3_10 * 2] += 1;
        } else {
            s.bl_tree[REPZ_11_138 * 2] += 1;
        }

        count = 0;
        prevlen = curlen as i32;

        if nextlen == 0 {
            max_count = 138;
            min_count = 3;
        } else if curlen == nextlen {
            max_count = 6;
            min_count = 3;
        } else {
            max_count = 7;
            min_count = 4;
        }
    }

    match kind {
        TreeKind::Literal => s.dyn_ltree = tree,
        TreeKind::Distance => s.dyn_dtree = tree,
        TreeKind::BitLength => s.bl_tree = tree,
    }
}

/// Send a literal or distance tree in compressed form, using the codes in
/// `bl_tree`.
fn send_tree(s: &mut DeflateState, kind: TreeKind) {
    let max_code = s.max_code(kind);
    let tree = std::mem::take(match kind {
        TreeKind::Literal => &mut s.dyn_ltree,
        TreeKind::Distance => &mut s.dyn_dtree,
        TreeKind::BitLength => &mut s.bl_tree,
    });
    let bl = std::mem::take(&mut s.bl_tree);

    let mut prevlen: i32 = -1;
    let mut nextlen = tree[1] as usize;
    let mut count = 0usize;
    let mut max_count = 7usize;
    let mut min_count = 4usize;

    /* tree[max_code+1].Len = -1: the guard is already set by scan_tree */
    if nextlen == 0 {
        max_count = 138;
        min_count = 3;
    }

    for n in 0..=max_code.max(-1) {
        let n = n as usize;
        let curlen = nextlen;
        nextlen = tree[(n + 1) * 2 + 1] as usize;

        count += 1;
        if count < max_count && curlen == nextlen {
            continue;
        } else if count < min_count {
            loop {
                send_code(s, curlen, &bl);
                count -= 1;
                if count == 0 {
                    break;
                }
            }
        } else if curlen != 0 {
            if curlen as i32 != prevlen {
                send_code(s, curlen, &bl);
                count -= 1;
            }
            send_code(s, REP_3_6, &bl);
            send_bits(s, (count - 3) as u32, 2);
        } else if count <= 10 {
            send_code(s, REPZ_3_10, &bl);
            send_bits(s, (count - 3) as u32, 3);
        } else {
            send_code(s, REPZ_11_138, &bl);
            send_bits(s, (count - 11) as u32, 7);
        }

        count = 0;
        prevlen = curlen as i32;
        if nextlen == 0 {
            max_count = 138;
            min_count = 3;
        } else if curlen == nextlen {
            max_count = 6;
            min_count = 3;
        } else {
            max_count = 7;
            min_count = 4;
        }
    }

    s.bl_tree = bl;
    match kind {
        TreeKind::Literal => s.dyn_ltree = tree,
        TreeKind::Distance => s.dyn_dtree = tree,
        TreeKind::BitLength => s.bl_tree = tree,
    }
}

/// Construct the Huffman tree for the bit lengths and return the index in
/// `BL_ORDER` of the last bit length code to send.
fn build_bl_tree(s: &mut DeflateState) -> usize {
    /* Determine the bit length frequencies for the literal and distance trees */
    scan_tree(s, TreeKind::Literal);
    scan_tree(s, TreeKind::Distance);

    /* Build the bit length tree. opt_len now includes the length of the tree
     * representations, except the bit length code lengths and the 5+5+4 bits
     * for the counts. */
    build_tree(s, TreeKind::BitLength);

    /* Determine the number of bit length codes to send. The pkzip format
     * requires at least 4 to be sent (appnote.txt says 3, but 4 is used). */
    let mut max_blindex = BL_CODES - 1;
    while max_blindex >= 3 {
        if s.bl_tree[BL_ORDER[max_blindex] as usize * 2 + 1] != 0 {
            break;
        }
        max_blindex -= 1;
    }

    /* Update opt_len to include the bit length tree and counts */
    s.opt_len += (3 * (max_blindex + 1) + 5 + 5 + 4) as isize;

    max_blindex
}

/// Send the header for a block using dynamic Huffman trees: the counts, the
/// lengths of the bit length codes, the literal tree and the distance tree.
fn send_all_trees(s: &mut DeflateState, lcodes: usize, dcodes: usize, blcodes: usize) {
    send_bits(s, (lcodes - 257) as u32, 5); /* not +255 as stated in appnote.txt */
    send_bits(s, (dcodes - 1) as u32, 5);
    send_bits(s, (blcodes - 4) as u32, 4); /* not -3 as stated in appnote.txt */
    for &rank in BL_ORDER.iter().take(blcodes) {
        let v = s.bl_tree[rank as usize * 2 + 1] as u32;
        send_bits(s, v, 3);
    }

    send_tree(s, TreeKind::Literal);
    send_tree(s, TreeKind::Distance);
}

/// Decide whether the data is TEXT or BINARY.
///
/// TEXT when there are no non-portable control characters from the block list
/// (0..6, 14..25, 28..31) and at least one printable character from the allow
/// list (9 TAB, 10 LF, 13 CR, 32..255). The gray list (7, 8, 11, 12, 26, 27)
/// is ignored.
fn detect_data_type(s: &DeflateState) -> i32 {
    /* 0xf3ffc07f is the bit mask of block-listed bytes: bits 0..6, 14..25,
     * 28..31 */
    let mut block_mask: u32 = 0xf3ff_c07f;

    for n in 0..=31usize {
        if block_mask & 1 != 0 && s.dyn_ltree[n * 2] != 0 {
            return Z_BINARY;
        }
        block_mask >>= 1;
    }

    if s.dyn_ltree[9 * 2] != 0 || s.dyn_ltree[10 * 2] != 0 || s.dyn_ltree[13 * 2] != 0 {
        return Z_TEXT;
    }
    for n in 32..LITERALS {
        if s.dyn_ltree[n * 2] != 0 {
            return Z_TEXT;
        }
    }

    /* No block-listed or allow-listed bytes: the stream is empty or holds
     * tolerated gray-listed bytes only. */
    Z_BINARY
}

/// Initialize the tree data structures for a new zlib stream.
pub fn tr_init(s: &mut DeflateState) {
    static_tables();

    s.bi_buf = 0;
    s.bi_valid = 0;

    /* Initialize the first block of the first file */
    init_block(s);
}

/// Send a stored block.
pub fn tr_stored_block(s: &mut DeflateState, buf: isize, stored_len: usize, last: bool) {
    send_bits(
        s,
        ((STORED_BLOCK << 1) + if last { 1 } else { 0 }) as u32,
        3,
    ); /* block type */
    bi_windup(s); /* align on byte boundary */
    put_short(s, stored_len as u32);
    put_short(s, !(stored_len as u32));
    if stored_len != 0 {
        let from = buf as usize;
        let pending = s.pending;
        let window = std::mem::take(&mut s.window);
        s.pending_buf[pending..pending + stored_len]
            .copy_from_slice(&window[from..from + stored_len]);
        s.window = window;
    }
    s.pending += stored_len;
}

/// Send one empty static block to give enough lookahead for inflate.
///
/// This takes 10 bits, of which 7 may remain in the bit buffer.
pub fn tr_align(s: &mut DeflateState) {
    send_bits(s, (STATIC_TREES << 1) as u32, 3);
    let ltree = &static_tables().static_ltree;
    send_code(s, END_BLOCK, ltree);
    bi_flush(s);
}

/// Determine the best encoding for the current block (dynamic trees, static
/// trees or stored) and write it out.
///
/// `buf` is the window index of the input block, or `-1` when the block is too
/// old to be re-sent as a stored block.
pub fn tr_flush_block(
    s: &mut DeflateState,
    buf: isize,
    stored_len: usize,
    last: bool,
    strm_data_type: &mut i32,
) {
    let mut opt_lenb: usize;
    let static_lenb: usize;
    let mut max_blindex = 0usize;

    /* Build the Huffman trees unless a stored block is forced */
    if s.level > 0 {
        /* Check whether the file is binary or text */
        if *strm_data_type == Z_UNKNOWN {
            *strm_data_type = detect_data_type(s);
        }

        /* Construct the literal and distance trees */
        build_tree(s, TreeKind::Literal);
        build_tree(s, TreeKind::Distance);

        /* Build the bit length tree for the above two trees, and get the index
         * in BL_ORDER of the last bit length code to send. */
        max_blindex = build_bl_tree(s);

        /* Determine the best encoding. Compute the block lengths in bytes. */
        // `>>> 3` in the original is an unsigned shift, so JavaScript applies
        // ToUint32 first: a negative accumulator becomes a huge positive
        // before shifting. `as u32` on a negative isize truncates identically.
        opt_lenb = (((s.opt_len + 10) as u32) >> 3) as usize;
        static_lenb = (((s.static_len + 10) as u32) >> 3) as usize;

        if static_lenb <= opt_lenb || s.strategy == Z_FIXED {
            opt_lenb = static_lenb;
        }
    } else {
        opt_lenb = stored_len + 5; /* force a stored block */
        static_lenb = opt_lenb;
    }

    if stored_len + 4 <= opt_lenb && buf != -1 {
        /* 4: two words for the lengths.
         *
         * The buf != -1 test is only needed when LIT_BUFSIZE > WSIZE:
         * otherwise no more than WSIZE input bytes can have been processed
         * since the last block flush, so it is never too late to turn a block
         * into a stored block. */
        tr_stored_block(s, buf, stored_len, last);
    } else if s.strategy == Z_FIXED || static_lenb == opt_lenb {
        send_bits(
            s,
            ((STATIC_TREES << 1) + if last { 1 } else { 0 }) as u32,
            3,
        );
        let t = static_tables();
        let (ltree, dtree) = (&t.static_ltree, &t.static_dtree);
        compress_block(s, ltree, dtree);
    } else {
        send_bits(s, ((DYN_TREES << 1) + if last { 1 } else { 0 }) as u32, 3);
        let lcodes = (s.l_max_code + 1) as usize;
        let dcodes = (s.d_max_code + 1) as usize;
        send_all_trees(s, lcodes, dcodes, max_blindex + 1);
        let ltree = std::mem::take(&mut s.dyn_ltree);
        let dtree = std::mem::take(&mut s.dyn_dtree);
        compress_block(s, &ltree, &dtree);
        s.dyn_ltree = ltree;
        s.dyn_dtree = dtree;
    }

    init_block(s);

    if last {
        bi_windup(s);
    }
}

/// Save the match info and tally the frequency counts. Returns true when the
/// current block must be flushed.
pub fn tr_tally(s: &mut DeflateState, dist: usize, lc: usize) -> bool {
    s.pending_buf[s.sym_buf + s.sym_next] = (dist & 0xff) as u8;
    s.sym_next += 1;
    s.pending_buf[s.sym_buf + s.sym_next] = ((dist >> 8) & 0xff) as u8;
    s.sym_next += 1;
    s.pending_buf[s.sym_buf + s.sym_next] = (lc & 0xff) as u8;
    s.sym_next += 1;

    if dist == 0 {
        /* lc is the unmatched char */
        s.dyn_ltree[lc * 2] += 1;
    } else {
        s.matches += 1;
        /* Here lc is the match length - MIN_MATCH */
        let dist = dist - 1; /* dist = match distance - 1 */
        let t = static_tables();
        let lcode = t.length_code[lc] as usize;
        s.dyn_ltree[(lcode + LITERALS + 1) * 2] += 1;
        s.dyn_dtree[d_code(dist) * 2] += 1;
    }

    s.sym_next == s.sym_end
}

#[cfg(test)]
mod tests {
    // Every expected value came from running the JavaScript original
    // (src/zlib/trees.mjs) over the same input; see the oracle scripts in the
    // port notes. A whole-table checksum is used where a table is opaque.
    use super::*;
    use crate::zlib::crc32::crc32;

    fn sig_u16(t: &[u16]) -> String {
        let mut bytes = Vec::with_capacity(t.len() * 2);
        for &v in t {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        format!("{:08X}", crc32(0, &bytes, bytes.len(), 0))
    }

    fn sig_u8(t: &[u8]) -> String {
        format!("{:08X}", crc32(0, t, t.len(), 0))
    }

    #[test]
    fn bi_reverse_reverses_the_low_bits() {
        assert_eq!(bi_reverse(0b0000_0001, 5), 0b0001_0000);
        assert_eq!(bi_reverse(0b0001_0000, 5), 0b0000_0001);
        assert_eq!(bi_reverse(0b101_0101_0101_0101, 15), 0b101_0101_0101_0101);
        assert_eq!(bi_reverse(0, 1), 0);
        assert_eq!(bi_reverse(1, 1), 1);
    }

    #[test]
    fn static_length_and_distance_maps_match_the_oracle() {
        let t = static_tables();
        assert_eq!(t.length_code.len(), 256);
        assert_eq!(t.dist_code.len(), 512);
        // length 255 (match length 258) is coded as 285, not 284 + 5 extra.
        assert_eq!(t.length_code[255], 28);
        assert_eq!(t.base_length[0], 0);
        assert_eq!(t.base_dist[0], 0);
        assert_eq!(t.base_dist[D_CODES - 1], 24576);
        assert_eq!(t.dist_code[255], 15);
        assert_eq!(t.dist_code[258], 16);
        assert_eq!(t.dist_code[511], 29);
        assert_eq!(sig_u8(&t.length_code), "D0D6FAA6");
        assert_eq!(sig_u8(&t.dist_code), "1DA7070B");
    }

    #[test]
    fn static_trees_match_the_oracle() {
        let t = static_tables();
        // Lengths are imposed by the deflate format: 8, 9, 7, 8.
        assert_eq!(t.static_ltree[1], 8);
        assert_eq!(t.static_ltree[144 * 2 + 1], 9);
        assert_eq!(t.static_ltree[256 * 2 + 1], 7);
        assert_eq!(t.static_ltree[280 * 2 + 1], 8);
        // Every static distance code is 5 bits.
        assert!((0..D_CODES).all(|n| t.static_dtree[n * 2 + 1] == 5));
        assert_eq!(sig_u16(&t.static_ltree), "2E85931B");
        assert_eq!(sig_u16(&t.static_dtree), "86C1E1F4");
    }

    #[test]
    fn d_code_maps_distances_to_their_codes() {
        assert_eq!(d_code(0), 0);
        assert_eq!(d_code(1), 1);
        assert_eq!(d_code(255), static_tables().dist_code[255] as usize);
        assert_eq!(d_code(256), static_tables().dist_code[256 + 2] as usize);
        assert_eq!(d_code(32767), static_tables().dist_code[256 + 255] as usize);
    }

    #[test]
    fn static_tables_are_built_once() {
        assert!(std::ptr::eq(static_tables(), static_tables()));
    }

    #[test]
    fn detect_data_type_follows_the_block_and_allow_lists() {
        let mut s = DeflateState::new();
        // A block-listed control byte makes it binary.
        s.dyn_ltree[0] = 1;
        assert_eq!(detect_data_type(&s), Z_BINARY);

        // Tab, LF and CR are allow-listed.
        let mut s = DeflateState::new();
        s.dyn_ltree[9 * 2] = 1;
        assert_eq!(detect_data_type(&s), Z_TEXT);

        // A printable byte is allow-listed.
        let mut s = DeflateState::new();
        s.dyn_ltree[b'A' as usize * 2] = 1;
        assert_eq!(detect_data_type(&s), Z_TEXT);

        // Gray-listed bytes only: neither list fires, so binary.
        let mut s = DeflateState::new();
        s.dyn_ltree[7 * 2] = 1;
        assert_eq!(detect_data_type(&s), Z_BINARY);

        // Empty is binary.
        assert_eq!(detect_data_type(&DeflateState::new()), Z_BINARY);
    }

    #[test]
    fn send_bits_spills_into_pending_at_sixteen_bits() {
        let mut s = DeflateState::new();
        s.pending_buf = vec![0u8; 64];

        send_bits(&mut s, 0b101, 3);
        assert_eq!((s.bi_valid, s.pending), (3, 0), "no spill below 16 bits");

        send_bits(&mut s, 0xFFFF, 16);
        assert_eq!(s.pending, 2, "a 16-bit value must spill two bytes");
        // Low 3 bits are the first value, the rest the start of the second.
        assert_eq!(s.pending_buf[0], 0b1111_1101);
        assert_eq!(s.pending_buf[1], 0xFF);
        assert_eq!(s.bi_valid, 3);
    }

    #[test]
    fn bi_windup_aligns_on_a_byte_boundary() {
        let mut s = DeflateState::new();
        s.pending_buf = vec![0u8; 64];

        send_bits(&mut s, 0b1, 1);
        bi_windup(&mut s);
        assert_eq!((s.pending, s.bi_buf, s.bi_valid), (1, 0, 0));
        assert_eq!(s.pending_buf[0], 1);

        // More than 8 valid bits writes a whole short.
        let mut s = DeflateState::new();
        s.pending_buf = vec![0u8; 64];
        send_bits(&mut s, 0x1FF, 9);
        bi_windup(&mut s);
        assert_eq!(s.pending, 2);
        assert_eq!((s.pending_buf[0], s.pending_buf[1]), (0xFF, 0x01));
    }

    #[test]
    fn tr_align_emits_an_empty_static_block() {
        let mut s = DeflateState::new();
        s.pending_buf = vec![0u8; 64];
        tr_init(&mut s);
        tr_align(&mut s);
        // 3 bits of block header plus the 7-bit END_BLOCK code is 10 bits, so
        // one byte lands in pending and at most 7 bits stay buffered.
        assert_eq!(s.pending, 1);
        assert!(s.bi_valid <= 7, "at most 7 bits may remain buffered");
    }

    #[test]
    fn init_block_seeds_the_end_of_block_frequency() {
        let mut s = DeflateState::new();
        s.dyn_ltree[4] = 99;
        init_block(&mut s);
        assert_eq!(s.dyn_ltree[END_BLOCK * 2], 1, "END_BLOCK must start at 1");
        assert_eq!(s.dyn_ltree[4], 0);
        assert_eq!(
            (s.opt_len, s.static_len, s.sym_next, s.matches),
            (0, 0, 0, 0)
        );
    }

    #[test]
    fn tr_tally_counts_literals_and_matches() {
        let mut s = DeflateState::new();
        s.pending_buf = vec![0u8; 4096];
        s.lit_bufsize = 256;
        s.sym_buf = 256;
        s.sym_end = (s.lit_bufsize - 1) * 3;
        init_block(&mut s);

        assert!(!tr_tally(&mut s, 0, b'A' as usize));
        assert_eq!(s.dyn_ltree[b'A' as usize * 2], 1);
        assert_eq!(s.sym_next, 3);
        assert_eq!(s.matches, 0);

        // A match of length 3 (lc 0) at distance 1.
        assert!(!tr_tally(&mut s, 1, 0));
        assert_eq!(s.matches, 1);
        assert_eq!(s.dyn_dtree[d_code(0) * 2], 1);
        let lcode = static_tables().length_code[0] as usize;
        assert_eq!(s.dyn_ltree[(lcode + LITERALS + 1) * 2], 1);
    }
}
