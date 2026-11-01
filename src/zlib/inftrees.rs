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

//! Builds the Huffman decoding tables that `inflate` and `inffast` read.

const MAXBITS: usize = 15;
const ENOUGH_LENS: usize = 852;
const ENOUGH_DISTS: usize = 592;

/// Which alphabet a table is being built for.
///
/// The original passes the magic integers 0, 1 and 2. They never cross the
/// crate boundary, so an enum is used instead; the three arms select the same
/// `base`/`extra` tables and `match` thresholds as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeType {
    /// The code-length alphabet (19 symbols), read before the real tables.
    Codes,
    /// Literal/length codes.
    Lens,
    /// Distance codes.
    Dists,
}

/* Length codes 257..285 base */
const LBASE: [u16; 31] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258, 0, 0,
];

/* Length codes 257..285 extra */
const LEXT: [u8; 31] = [
    16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18, 19, 19, 19, 19, 20, 20, 20, 20,
    21, 21, 21, 21, 16, 199, 75,
];

/* Distance codes 0..29 base */
const DBASE: [u16; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 0, 0,
];

/* Distance codes 0..29 extra */
const DEXT: [u8; 32] = [
    16, 16, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22, 23, 23, 24, 24, 25, 25, 26, 26,
    27, 27, 28, 28, 29, 29, 64, 64,
];

/// Build a Huffman decoding table from the code lengths in `lens`.
///
/// Returns `0` on success, `-1` for an over-subscribed or incomplete set, and
/// `1` when the table would not fit in the space the caller provided. `bits`
/// is in/out: the caller passes the requested root size and reads back the
/// size actually used, replacing the original's `opts.bits` object.
///
/// Entries are packed exactly as the original packs them, into one signed
/// 32-bit word per entry: `(bits << 24) | (op << 16) | val`. The element type
/// is `i32` rather than `u32` because the JavaScript tables are `Int32Array`
/// and `inflate` reads them back with an unsigned shift; every value this
/// function writes is positive, so the two agree, but keeping `i32` means a
/// future entry that did set the top bit would diverge here rather than
/// silently in the decoder.
///
/// Unlike the original this takes no `table_index`: all five call sites pass
/// zero. Dropping it also removes an inconsistency in the original, where the
/// root-table back-pointer is written to `table[low]` while every other write
/// is relative to `table_index`.
pub fn inflate_table(
    code_type: CodeType,
    lens: &[u16],
    lens_index: usize,
    codes: usize,
    table: &mut [i32],
    work: &mut [u16],
    bits: &mut usize,
) -> i32 {
    let mut len: usize;
    let mut sym: usize;
    let mut min: u32;
    let mut max: usize;
    let mut root: usize = *bits;
    let mut curr: usize;
    let mut drop: usize;
    let mut left: i32;
    let mut used: usize;
    let mut huff: u32;
    let mut incr: u32;
    let mut fill: u32;
    let mut low: i64;
    let mut next: usize;
    let mut count = [0u16; MAXBITS + 1];
    let mut offs = [0u16; MAXBITS + 1];

    /* accumulate lengths for codes (assumes lens[] all in 0..MAXBITS) */
    for sym in 0..codes {
        count[lens[lens_index + sym] as usize] += 1;
    }

    /* bound code lengths, force root to be within code lengths */
    max = MAXBITS;
    while max >= 1 {
        if count[max] != 0 {
            break;
        }
        max -= 1;
    }
    if root > max {
        root = max;
    }
    if max == 0 {
        /* no symbols to code at all: two invalid-code markers, and wait for
         * the decoder to report the error */
        table[0] = (1 << 24) | (64 << 16);
        table[1] = (1 << 24) | (64 << 16);
        *bits = 1;
        return 0;
    }
    min = 1;
    while (min as usize) < max {
        if count[min as usize] != 0 {
            break;
        }
        min += 1;
    }
    if root < min as usize {
        root = min as usize;
    }

    /* check for an over-subscribed or incomplete set of lengths */
    left = 1;
    for &c in count.iter().skip(1) {
        left <<= 1;
        left -= c as i32;
        if left < 0 {
            return -1; /* over-subscribed */
        }
    }
    if left > 0 && (code_type == CodeType::Codes || max != 1) {
        return -1; /* incomplete set */
    }

    /* generate offsets into symbol table for each length for sorting */
    offs[1] = 0;
    for len in 1..MAXBITS {
        offs[len + 1] = offs[len] + count[len];
    }

    /* sort symbols by length, by symbol order within each length */
    for sym in 0..codes {
        if lens[lens_index + sym] != 0 {
            let slot = offs[lens[lens_index + sym] as usize];
            work[slot as usize] = sym as u16;
            offs[lens[lens_index + sym] as usize] = slot + 1;
        }
    }

    /* set up for code type.
     *
     * The original assigns `base = extra = work` for Codes as an explicitly
     * dummy value. That would alias `work`, which Rust forbids, and it is
     * unreachable anyway: Codes is only ever called with 19 symbols, so
     * `work[sym] <= 18` is always below the match threshold of 20 and the
     * branch reading base/extra is never taken. Empty slices make that
     * explicit and would panic rather than read nonsense if it ever were. */
    let (base, extra, matches): (&[u16], &[u8], usize) = match code_type {
        CodeType::Codes => (&[], &[], 20),
        CodeType::Lens => (&LBASE, &LEXT, 257),
        CodeType::Dists => (&DBASE, &DEXT, 0),
    };

    /* initialize state for the loop */
    huff = 0;
    sym = 0;
    len = min as usize;
    next = 0;
    curr = root;
    drop = 0;
    low = -1;
    used = 1usize << root;
    let mask = (used - 1) as u32;

    /* check available table space */
    if (code_type == CodeType::Lens && used > ENOUGH_LENS)
        || (code_type == CodeType::Dists && used > ENOUGH_DISTS)
    {
        return 1;
    }

    /* process all codes and make table entries */
    loop {
        /* create table entry */
        let here_bits = (len - drop) as i32;
        let (here_op, here_val): (i32, i32) = if (work[sym] as usize) + 1 < matches {
            (0, work[sym] as i32)
        } else if (work[sym] as usize) >= matches {
            (
                extra[work[sym] as usize - matches] as i32,
                base[work[sym] as usize - matches] as i32,
            )
        } else {
            (32 + 64, 0) /* end of block */
        };

        /* replicate for those indices with low len bits equal to huff */
        incr = 1 << (len - drop);
        fill = 1 << curr;
        min = fill; /* save offset to next table */
        loop {
            fill -= incr;
            table[next + (huff >> drop) as usize + fill as usize] =
                (here_bits << 24) | (here_op << 16) | here_val;
            if fill == 0 {
                break;
            }
        }

        /* backwards increment the len-bit code huff */
        incr = 1 << (len - 1);
        while huff & incr != 0 {
            incr >>= 1;
        }
        if incr != 0 {
            huff &= incr - 1;
            huff += incr;
        } else {
            huff = 0;
        }

        /* go to next symbol, update count, len */
        sym += 1;
        count[len] -= 1;
        if count[len] == 0 {
            if len == max {
                break;
            }
            len = lens[lens_index + work[sym] as usize] as usize;
        }

        /* create new sub-table if needed */
        if len > root && (huff & mask) as i64 != low {
            /* if first time, transition to sub-tables */
            if drop == 0 {
                drop = root;
            }

            /* increment past last table */
            next += min as usize; /* here min is 1 << curr */

            /* determine length of next table */
            curr = len - drop;
            left = 1 << curr;
            while curr + drop < max {
                left -= count[curr + drop] as i32;
                if left <= 0 {
                    break;
                }
                curr += 1;
                left <<= 1;
            }

            /* check for enough space */
            used += 1 << curr;
            if (code_type == CodeType::Lens && used > ENOUGH_LENS)
                || (code_type == CodeType::Dists && used > ENOUGH_DISTS)
            {
                return 1;
            }

            /* point entry in root table to sub-table */
            low = (huff & mask) as i64;
            table[low as usize] = ((root as i32) << 24) | ((curr as i32) << 16) | (next as i32);
        }
    }

    /* fill in remaining table entry if code is incomplete (guaranteed to have
     * at most one remaining entry, since if the code is incomplete, the
     * maximum code length that was allowed to get this far is one bit) */
    if huff != 0 {
        table[next + huff as usize] = (((len - drop) as i32) << 24) | (64 << 16);
    }

    *bits = root;
    0
}

#[cfg(test)]
mod tests {
    // Every `crc` and `bits` below was produced by running the JavaScript
    // original (src/zlib/inftrees.mjs) on the same code lengths. A whole-table
    // checksum is asserted rather than individual entries because the packed
    // words are opaque: a single wrong `op` nibble in any of 852 slots has to
    // fail the test, and spot checks would miss it.
    use super::{inflate_table, CodeType};
    use crate::zlib::crc32::crc32;

    /// CRC-32 over the little-endian bytes of every table entry.
    fn sig(table: &[i32]) -> String {
        let mut bytes = Vec::with_capacity(table.len() * 4);
        for &v in table {
            bytes.extend_from_slice(&(v as u32).to_le_bytes());
        }
        format!("{:08X}", crc32(0, &bytes, bytes.len(), 0))
    }

    /// A unary chain 1,2,3,..,n-1,n-1 is a complete canonical code: the code
    /// lengths satisfy Kraft equality, sum of 2^-len == 1. Used to get a
    /// valid code whose maximum length exceeds the root, which is the only
    /// way to reach the sub-table construction path.
    fn unary(n: usize) -> Vec<u16> {
        let mut v: Vec<u16> = (1..n as u16).collect();
        v.push(n as u16 - 1);
        v
    }

    fn build(
        code_type: CodeType,
        lens_in: &[u16],
        codes: usize,
        size: usize,
        bits_in: usize,
    ) -> (i32, usize, String) {
        let mut lens = vec![0u16; 320];
        lens[..lens_in.len()].copy_from_slice(lens_in);
        let mut table = vec![0i32; size];
        let mut work = vec![0u16; 288];
        let mut bits = bits_in;
        let ret = inflate_table(code_type, &lens, 0, codes, &mut table, &mut work, &mut bits);
        (ret, bits, sig(&table))
    }

    #[test]
    fn builds_the_fixed_literal_length_table() {
        let mut lens = vec![0u16; 320];
        for (sym, l) in lens.iter_mut().enumerate().take(288) {
            *l = match sym {
                0..=143 => 8,
                144..=255 => 9,
                256..=279 => 7,
                _ => 8,
            };
        }
        let mut table = vec![0i32; 512];
        let mut work = vec![0u16; 288];
        let mut bits = 9usize;
        let ret = inflate_table(
            CodeType::Lens,
            &lens,
            0,
            288,
            &mut table,
            &mut work,
            &mut bits,
        );
        assert_eq!((ret, bits), (0, 9));
        assert_eq!(sig(&table), "26385EE9");
        assert_eq!(
            [table[0], table[1], table[2], table[255], table[256], table[511]],
            [123731968, 134217808, 134217744, 150995198, 123731968, 150995199]
        );
    }

    #[test]
    fn builds_the_fixed_distance_table() {
        let (ret, bits, crc) = build(CodeType::Dists, &[5u16; 32], 32, 32, 5);
        assert_eq!((ret, bits, crc.as_str()), (0, 5, "5E4AA16B"));
    }

    #[test]
    fn builds_multi_level_sub_tables() {
        // Max length 15 against a root of 9 is the only configuration that
        // drives the `len > root` branch, `drop = root` and the look-ahead
        // that sizes each sub-table.
        let (ret, bits, crc) = build(CodeType::Lens, &unary(16), 288, 852, 9);
        assert_eq!((ret, bits, crc.as_str()), (0, 9, "D8B00314"));

        let (ret, bits, crc) = build(CodeType::Dists, &unary(16), 32, 592, 6);
        assert_eq!((ret, bits, crc.as_str()), (0, 6, "BC9789FC"));
    }

    #[test]
    fn builds_the_code_length_alphabet() {
        let (ret, bits, crc) = build(CodeType::Codes, &unary(8), 19, 852, 7);
        assert_eq!((ret, bits, crc.as_str()), (0, 7, "6F1F329B"));
    }

    #[test]
    fn accepts_a_single_one_bit_code_only_for_lens_and_dists() {
        // An incomplete set is tolerated when max == 1, which is how a block
        // carrying one distance code stays legal. Codes never gets that pass.
        let (ret, bits, crc) = build(CodeType::Lens, &[1], 19, 852, 7);
        assert_eq!((ret, bits, crc.as_str()), (0, 1, "019D066F"));

        let (ret, _, _) = build(CodeType::Codes, &[1], 19, 852, 7);
        assert_eq!(ret, -1, "Codes must reject an incomplete set");
    }

    #[test]
    fn rejects_an_over_subscribed_set() {
        let (ret, _, _) = build(CodeType::Lens, &[1, 1, 1], 3, 852, 7);
        assert_eq!(ret, -1);
    }

    #[test]
    fn writes_two_invalid_markers_when_there_are_no_symbols() {
        let (ret, bits, _) = build(CodeType::Lens, &[], 19, 852, 7);
        assert_eq!((ret, bits), (0, 1));

        let mut lens = vec![0u16; 320];
        let mut table = vec![0i32; 852];
        let mut work = vec![0u16; 288];
        let mut bits = 7usize;
        inflate_table(
            CodeType::Lens,
            &lens,
            0,
            19,
            &mut table,
            &mut work,
            &mut bits,
        );
        assert_eq!([table[0], table[1]], [20971520, 20971520]);
        lens[0] = 0;
    }

    #[test]
    fn reports_out_of_space_rather_than_overrunning() {
        // Requesting root 1 for a code whose shortest length is 1 but which
        // needs 15 levels exhausts ENOUGH_LENS; the original returns 1.
        let (ret, bits, crc) = build(CodeType::Lens, &unary(16), 288, 852, 1);
        assert_eq!((ret, bits, crc.as_str()), (1, 1, "879D6166"));
    }
}
