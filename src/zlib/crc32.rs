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

//! CRC-32 (IEEE, reflected) with zlib's slicing-by-8 table.

/// Slicing-by-8 tables: 8 x 256 entries in one flat array.
///
/// The JavaScript original builds this at module load. A `const fn` builds it
/// at compile time instead, which keeps the crate dependency-free and avoids a
/// lazy-initialisation check on every call.
const fn make_table() -> [u32; 256 * 8] {
    let mut table = [0u32; 256 * 8];

    let mut n = 0usize;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }

    let mut n = 0usize;
    while n < 256 {
        let mut c = table[n];
        let mut k = 256usize;
        while k < 256 * 8 {
            c = table[(c & 0xFF) as usize] ^ (c >> 8);
            table[k + n] = c;
            k += 256;
        }
        n += 1;
    }

    table
}

static CRC_TABLE: [u32; 256 * 8] = make_table();

/// CRC-32 of `buf[pos .. pos + len]`, continuing from `crc`.
///
/// Eight bytes are folded per iteration while at least eight remain, then the
/// tail is handled a byte at a time. The `end >= 7` guard replaces the
/// original's `end - 7` loop bound, which would underflow on a `usize`.
pub fn crc32(crc: u32, buf: &[u8], len: usize, pos: usize) -> u32 {
    let t = &CRC_TABLE;
    let end = pos + len;
    let mut i = pos;
    let mut crc = crc ^ 0xFFFF_FFFF;

    // Process 8 bytes per iteration (slicing-by-8)
    if end >= 7 {
        let end8 = end - 7;
        while i < end8 {
            crc ^= (buf[i] as u32)
                | ((buf[i + 1] as u32) << 8)
                | ((buf[i + 2] as u32) << 16)
                | ((buf[i + 3] as u32) << 24);
            crc = t[1792 + (crc & 0xFF) as usize]
                ^ t[1536 + ((crc >> 8) & 0xFF) as usize]
                ^ t[1280 + ((crc >> 16) & 0xFF) as usize]
                ^ t[1024 + (crc >> 24) as usize]
                ^ t[768 + buf[i + 4] as usize]
                ^ t[512 + buf[i + 5] as usize]
                ^ t[256 + buf[i + 6] as usize]
                ^ t[buf[i + 7] as usize];
            i += 8;
        }
    }

    while i < end {
        crc = (crc >> 8) ^ t[((crc ^ buf[i] as u32) & 0xFF) as usize];
        i += 1;
    }

    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    // As in adler32, every expected value came from running the JavaScript
    // original (src/zlib/crc32.mjs) on the same input.
    use super::crc32;

    #[test]
    fn matches_the_oracle_on_short_inputs() {
        assert_eq!(crc32(0, &[], 0, 0), 0x0000_0000);
        assert_eq!(crc32(0, b"123456789", 9, 0), 0xCBF4_3926);
        assert_eq!(crc32(0, b"Wikipedia", 9, 0), 0xADAA_C02E);
    }

    #[test]
    fn short_input_does_not_underflow_the_slice_by_8_bound() {
        // A port that wrote the original's `end - 7` loop bound on a usize
        // panics on these instead of taking the tail loop.
        assert_eq!(crc32(0, b"a", 1, 0), 0xE8B7_BE43);
        assert_eq!(crc32(0, b"abc", 3, 0), 0x3524_41C2);
    }

    #[test]
    fn matches_the_oracle_through_the_eight_wide_loop() {
        assert_eq!(
            crc32(0, &(0..64u8).collect::<Vec<u8>>(), 64, 0),
            0x100E_CE8C
        );
        assert_eq!(crc32(0, &vec![0xFFu8; 6000], 6000, 0), 0xB782_9FE5);
        assert_eq!(crc32(0, &vec![0xAAu8; 5551], 5551, 0), 0x8BAD_8B5D);
    }

    #[test]
    fn slicing_by_8_agrees_with_the_byte_at_a_time_tail() {
        let buf: Vec<u8> = (0..64u8).collect();
        let wide = crc32(0, &buf, buf.len(), 0);
        let mut narrow = 0u32;
        for i in 0..buf.len() {
            narrow = crc32(narrow, &buf, 1, i);
        }
        assert_eq!(wide, narrow);
    }

    #[test]
    fn honours_pos_and_len() {
        let buf = b"xx123456789xx";
        assert_eq!(crc32(0, buf, 9, 2), 0xCBF4_3926);
    }
}
