// Note: adler32 takes 12% for level 0 and 2% for level 6.
// It isn't worth it to make additional optimizations as in original.
// Small size is preferable.

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

/// Adler-32 checksum of `buf[pos .. pos + len]`, continuing from `adler`.
///
/// The JavaScript original forces every intermediate through `|0` to stay in
/// signed 32-bit range, because `%=` would otherwise be computed on a value
/// that had already lost precision. Rust's `u32` wraps natively, so the
/// `wrapping_add` calls below are the direct equivalent; the 2000-byte chunk
/// limit is kept so `s2` cannot pass 2^31 before the modulo, exactly as the
/// comment in the original explains.
pub fn adler32(adler: u32, buf: &[u8], len: usize, pos: usize) -> u32 {
    let mut s1 = adler & 0xffff;
    let mut s2 = (adler >> 16) & 0xffff;
    let mut p = pos;
    let mut left = len;

    while left != 0 {
        // Set limit ~ twice less than 5552, to keep
        // s2 in 31-bits, because we force signed ints.
        // in other case %= will fail.
        let mut n = if left > 2000 { 2000 } else { left };
        left -= n;

        loop {
            s1 = s1.wrapping_add(buf[p] as u32);
            p += 1;
            s2 = s2.wrapping_add(s1);
            n -= 1;
            if n == 0 {
                break;
            }
        }

        s1 %= 65521;
        s2 %= 65521;
    }

    s1 | (s2 << 16)
}

#[cfg(test)]
mod tests {
    // Every expected value here was produced by running the JavaScript
    // original (src/zlib/adler32.mjs) on the same input, not recalled from
    // memory. The JS implementation is the oracle this port has to match.
    use super::adler32;

    #[test]
    fn matches_the_oracle_on_short_inputs() {
        // adler32(1, "") == 1: the seed survives an empty buffer.
        assert_eq!(adler32(1, &[], 0, 0), 0x0000_0001);
        assert_eq!(adler32(1, b"a", 1, 0), 0x0062_0062);
        assert_eq!(adler32(1, b"abc", 3, 0), 0x024D_0127);
        assert_eq!(adler32(1, b"Wikipedia", 9, 0), 0x11E6_0398);
        assert_eq!(adler32(1, b"123456789", 9, 0), 0x091E_01DE);
    }

    #[test]
    fn crosses_the_2000_byte_chunk_boundary_three_times() {
        let buf = vec![0xFFu8; 6000];
        assert_eq!(adler32(1, &buf, buf.len(), 0), 0xA497_59EA);
    }

    #[test]
    fn straddles_the_5552_overflow_limit() {
        // 5552 is the largest block for which zlib's unchunked form keeps s2
        // inside 32 bits. Checking 5551 and 5552 catches a port that picked
        // the wrong side of that boundary.
        assert_eq!(adler32(1, &vec![0xAAu8; 5551], 5551, 0), 0x95E2_6709);
        assert_eq!(adler32(1, &vec![0xAAu8; 5552], 5552, 0), 0xFD95_67B3);
    }

    #[test]
    fn accumulates_across_calls_as_streaming_requires() {
        let buf = b"Wikipedia";
        let split = adler32(adler32(1, buf, 4, 0), buf, 5, 4);
        assert_eq!(split, adler32(1, buf, 9, 0));
    }

    #[test]
    fn honours_pos_and_len() {
        let buf = b"xxWikipediaxx";
        assert_eq!(adler32(1, buf, 9, 2), 0x11E6_0398);
    }
}
