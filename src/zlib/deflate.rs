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

//! The deflate encoder: the LZ77 engine and the five block compressors.

use super::adler32::adler32;
use super::constants::{
    Z_BLOCK, Z_BUF_ERROR, Z_DATA_ERROR, Z_DEFAULT_COMPRESSION, Z_DEFLATED, Z_FILTERED, Z_FINISH,
    Z_FIXED, Z_FULL_FLUSH, Z_HUFFMAN_ONLY, Z_NO_FLUSH, Z_OK, Z_PARTIAL_FLUSH, Z_RLE, Z_STREAM_END,
    Z_STREAM_ERROR, Z_UNKNOWN,
};
use super::crc32::crc32;
use super::deflate_state::{
    DeflateState, BS_BLOCK_DONE, BS_FINISH_DONE, BS_FINISH_STARTED, BS_NEED_MORE, BUSY_STATE,
    COMMENT_STATE, CONFIGURATION_TABLE, EXTRA_STATE, FINISH_STATE, GZIP_STATE, HCRC_STATE,
    INIT_STATE, MAX_MATCH, MAX_MEM_LEVEL, MAX_WBITS, MIN_LOOKAHEAD, MIN_MATCH, NAME_STATE, OS_CODE,
    PRESET_DICT,
};
use super::gzheader::GzHeader;
use super::messages::message;
use super::trees::{tr_align, tr_flush_block, tr_init, tr_stored_block, tr_tally};
use super::zstream::ZStream;

/// Maximum length of a stored (uncompressed) deflate block.
const MAX_STORED: usize = 65535;
/// A match further back than this is not worth taking at length `MIN_MATCH`.
const TOO_FAR: usize = 4096;

fn err(strm: &mut ZStream, error_code: i32) -> i32 {
    strm.msg = String::from(message(error_code));
    error_code
}

fn rank(f: i32) -> i32 {
    f * 2 - if f > 4 { 9 } else { 0 }
}

/// Read a window byte the way JavaScript does, where an index past the end
/// yields `undefined` and every bitwise use of it collapses to zero.
///
/// The 4-byte hash deliberately reads one byte beyond the three it needs, and
/// `fill_window` only guarantees `MIN_MATCH` of them, so this really is
/// reachable; indexing would panic where the original silently read zero.
fn win_byte(window: &[u8], i: usize) -> u32 {
    window.get(i).copied().unwrap_or(0) as u32
}

/// Compare two window positions with JavaScript's out-of-range semantics:
/// two reads past the end are `undefined === undefined`, which is true, while
/// one past and one inside is `undefined === byte`, which is false.
///
/// The unrolled scan loops below can run up to eight positions past the end of
/// the written data before their `scan < strend` guard is re-checked, so the
/// distinction decides whether a match is extended.
fn win_eq(window: &[u8], a: usize, b: usize) -> bool {
    match (window.get(a), window.get(b)) {
        (Some(x), Some(y)) => x == y,
        (None, None) => true,
        _ => false,
    }
}

/// Slide the hash table when sliding the window down.
///
/// Done even at level 0 so the table stays consistent if `deflateParams`
/// later switches to a non-zero level.
fn slide_hash(s: &mut DeflateState) {
    let wsize = s.w_size as u16;

    let mut p = s.hash_size;
    for _ in 0..s.hash_size {
        p -= 1;
        let m = s.head[p];
        s.head[p] = m.saturating_sub(wsize);
    }

    let mut p = s.w_size;
    for _ in 0..s.w_size {
        p -= 1;
        let m = s.prev[p];
        s.prev[p] = m.saturating_sub(wsize);
    }
}

/// Insert the string at `str_` into the dictionary and return the previous
/// head of its hash chain.
fn insert_string(s: &mut DeflateState, str_: usize) -> usize {
    let h = if s.legacy_hash {
        s.ins_h = ((s.ins_h << s.hash_shift) ^ win_byte(&s.window, str_ + MIN_MATCH - 1) as usize)
            & s.hash_mask;
        s.ins_h
    } else {
        // ANZAC++ hash: four bytes read little-endian, matching node.js zlib
        // output. The wrapping arithmetic reproduces the original's
        // `Math.imul(value, 66521) + 66521` under uint32 overflow exactly.
        let w = &s.window;
        let value = win_byte(w, str_)
            | (win_byte(w, str_ + 1) << 8)
            | (win_byte(w, str_ + 2) << 16)
            | (win_byte(w, str_ + 3) << 24);
        s.ins_h = ((value.wrapping_mul(66521).wrapping_add(66521) >> 16) as usize) & s.hash_mask;
        s.ins_h
    };

    let hash_head = s.head[h];
    let slot = str_ & s.w_mask;
    s.prev[slot] = hash_head;
    s.head[h] = str_ as u16;
    hash_head as usize
}

/// Flush as much pending output as possible.
fn flush_pending(strm: &mut ZStream, s: &mut DeflateState) {
    let mut len = s.pending;
    if len > strm.avail_out {
        len = strm.avail_out;
    }
    if len == 0 {
        return;
    }

    let next_out = strm.next_out;
    strm.output[next_out..next_out + len]
        .copy_from_slice(&s.pending_buf[s.pending_out..s.pending_out + len]);
    strm.next_out += len;
    s.pending_out += len;
    strm.total_out += len;
    strm.avail_out -= len;
    s.pending -= len;
    if s.pending == 0 {
        s.pending_out = 0;
    }
}

fn flush_block_only(strm: &mut ZStream, s: &mut DeflateState, last: bool) {
    let buf = if s.block_start >= 0 {
        s.block_start
    } else {
        -1
    };
    let stored_len = (s.strstart as isize - s.block_start) as usize;
    let mut data_type = strm.data_type;
    tr_flush_block(s, buf, stored_len, last, &mut data_type);
    strm.data_type = data_type;
    s.block_start = s.strstart as isize;
    flush_pending(strm, s);
}

fn put_byte(s: &mut DeflateState, b: u8) {
    s.pending_buf[s.pending] = b;
    s.pending += 1;
}

/// Put a short in the pending buffer, most significant byte first.
fn put_short_msb(s: &mut DeflateState, b: u32) {
    s.pending_buf[s.pending] = ((b >> 8) & 0xff) as u8;
    s.pending += 1;
    s.pending_buf[s.pending] = (b & 0xff) as u8;
    s.pending += 1;
}

/// Read input into the sliding window, updating the check value and counts.
fn read_buf_window(strm: &mut ZStream, s: &mut DeflateState, start: usize, size: usize) -> usize {
    let mut len = strm.avail_in;
    if len > size {
        len = size;
    }
    if len == 0 {
        return 0;
    }

    strm.avail_in -= len;

    let next_in = strm.next_in;
    s.window[start..start + len].copy_from_slice(&strm.input[next_in..next_in + len]);

    if s.wrap == 1 {
        strm.adler = adler32(strm.adler, &s.window, len, start);
    } else if s.wrap == 2 {
        strm.adler = crc32(strm.adler, &s.window, len, start);
    }

    strm.next_in += len;
    strm.total_in += len;
    len
}

/// The same, for the one caller in `deflate_stored` that copies input straight
/// through to the output buffer.
fn read_buf_output(strm: &mut ZStream, s: &DeflateState, start: usize, size: usize) -> usize {
    let mut len = strm.avail_in;
    if len > size {
        len = size;
    }
    if len == 0 {
        return 0;
    }

    strm.avail_in -= len;

    let next_in = strm.next_in;
    let mut output = std::mem::take(&mut strm.output);
    output[start..start + len].copy_from_slice(&strm.input[next_in..next_in + len]);

    if s.wrap == 1 {
        strm.adler = adler32(strm.adler, &output, len, start);
    } else if s.wrap == 2 {
        strm.adler = crc32(strm.adler, &output, len, start);
    }
    strm.output = output;

    strm.next_in += len;
    strm.total_in += len;
    len
}

/// Set `match_start` to the longest match starting at the current string and
/// return its length. Matches no longer than `prev_length` are discarded, in
/// which case the result is `prev_length` and `match_start` is garbage.
fn longest_match(s: &mut DeflateState, cur_match: usize) -> usize {
    let mut chain_length = s.max_chain_length;
    let mut scan = s.strstart;
    let mut best_len = s.prev_length;
    let mut nice_match = s.nice_match;
    let limit = s.strstart.saturating_sub(s.w_size - MIN_LOOKAHEAD);

    let win = std::mem::take(&mut s.window);
    let wmask = s.w_mask;

    let strend = s.strstart + MAX_MATCH;
    let mut scan_end1 = win.get(scan + best_len - 1).copied();
    let mut scan_end = win.get(scan + best_len).copied();

    /* Do not waste too much time if we already have a good match */
    if s.prev_length >= s.good_match {
        chain_length >>= 2;
    }
    /* Do not look for matches beyond the end of the input. This is necessary
     * to make deflate deterministic. */
    if nice_match > s.lookahead {
        nice_match = s.lookahead;
    }

    let mut cur_match = cur_match;
    loop {
        let mut m = cur_match;

        /* Skip to the next match if the length cannot increase, or if it is
         * less than two. */
        if win.get(m + best_len).copied() == scan_end
            && win.get(m + best_len - 1).copied() == scan_end1
            && win.get(m).copied() == win.get(scan).copied()
            && {
                m += 1;
                win.get(m).copied() == win.get(scan + 1).copied()
            }
        {
            /* The check at best_len-1 can be dropped: it is made again later.
             * scan[2] and match[2] need not be compared, since they are always
             * equal when the other bytes match, given equal hash keys and
             * HASH_BITS >= 8. */
            scan += 2;
            m += 1;

            /* Lookahead is checked only every 8th comparison; the 256th check
             * is made at strstart+258. */
            loop {
                let mut matched = true;
                for _ in 0..8 {
                    scan += 1;
                    m += 1;
                    if !win_eq(&win, scan, m) {
                        matched = false;
                        break;
                    }
                }
                if !matched || scan >= strend {
                    break;
                }
            }

            let len = MAX_MATCH - (strend - scan);
            scan = strend - MAX_MATCH;

            if len > best_len {
                s.match_start = cur_match;
                best_len = len;
                if len >= nice_match {
                    break;
                }
                scan_end1 = win.get(scan + best_len - 1).copied();
                scan_end = win.get(scan + best_len).copied();
            }
        }

        cur_match = s.prev[cur_match & wmask] as usize;
        chain_length -= 1;
        if cur_match <= limit || chain_length == 0 {
            break;
        }
    }

    s.window = win;

    if best_len <= s.lookahead {
        best_len
    } else {
        s.lookahead
    }
}

/// Fill the window when the lookahead becomes insufficient, updating
/// `strstart` and `lookahead`.
fn fill_window(strm: &mut ZStream, s: &mut DeflateState) {
    let w_size = s.w_size;

    loop {
        let mut more = s.window_size - s.lookahead - s.strstart;

        /* If the window is almost full and the lookahead insufficient, move
         * the upper half to the lower one to make room in the upper half. */
        if s.strstart >= w_size + (w_size - MIN_LOOKAHEAD) {
            s.window.copy_within(w_size..w_size + w_size - more, 0);
            // zlib declares match_start as an unsigned IPos, so this subtraction
            // wraps in C and goes negative in JavaScript. Neither value is read:
            // longest_match rewrites match_start before any use.
            s.match_start = s.match_start.wrapping_sub(w_size);
            s.strstart -= w_size;
            /* we now have strstart >= MAX_DIST */
            s.block_start -= w_size as isize;
            if s.insert > s.strstart {
                s.insert = s.strstart;
            }
            slide_hash(s);
            more += w_size;
        }
        if strm.avail_in == 0 {
            break;
        }

        let start = s.strstart + s.lookahead;
        let n = read_buf_window(strm, s, start, more);
        s.lookahead += n;

        /* Initialize the hash value now that there is some input */
        if !s.legacy_hash {
            /* The 4-byte hash reads one extra byte, so it needs one more
             * available than the classic hash does. */
            if s.lookahead + s.insert > MIN_MATCH {
                let mut str_ = s.strstart - s.insert;
                while s.insert != 0 {
                    insert_string(s, str_);
                    str_ += 1;
                    s.insert -= 1;
                    if s.lookahead + s.insert <= MIN_MATCH {
                        break;
                    }
                }
            }
        } else if s.lookahead + s.insert >= MIN_MATCH {
            let mut str_ = s.strstart - s.insert;
            s.ins_h = win_byte(&s.window, str_) as usize;
            s.ins_h =
                ((s.ins_h << s.hash_shift) ^ win_byte(&s.window, str_ + 1) as usize) & s.hash_mask;
            while s.insert != 0 {
                insert_string(s, str_);
                str_ += 1;
                s.insert -= 1;
                if s.lookahead + s.insert < MIN_MATCH {
                    break;
                }
            }
        }
        /* If the whole input has fewer than MIN_MATCH bytes, ins_h is garbage,
         * but that does not matter since only literals will be emitted. */

        if !(s.lookahead < MIN_LOOKAHEAD && strm.avail_in != 0) {
            break;
        }
    }
}

/// Copy without compression as much as possible from the input stream.
///
/// `s.matches` doubles as a count of pending hash-table slides, so that a
/// later `deflateParams` switch to a non-zero level can catch the table up: 1
/// means one slide, 2 means clear it, since two or more slides are equivalent.
fn deflate_stored(strm: &mut ZStream, s: &mut DeflateState, flush: i32) -> i32 {
    /* Smallest worthy block size when not flushing or finishing. 32K by
     * default, as small as 507 bytes for memLevel == 1. */
    let mut min_block = if s.pending_buf_size - 5 > s.w_size {
        s.w_size
    } else {
        s.pending_buf_size - 5
    };

    let mut len: usize;
    let mut left: usize;
    let mut have: usize;
    let mut last = false;
    let mut used = strm.avail_in;

    loop {
        /* Set len to the largest block that can be copied directly with the
         * available input and output space, and left to how much of that comes
         * from what is still in the window. */
        len = MAX_STORED;
        have = (s.bi_valid + 42) >> 3; /* number of header bytes */
        if strm.avail_out < have {
            break; /* need room for the header */
        }
        have = strm.avail_out - have;
        left = (s.strstart as isize - s.block_start) as usize;
        if len > left + strm.avail_in {
            len = left + strm.avail_in;
        }
        if len > have {
            len = have;
        }

        /* If the stored block would be shorter than min_block, or if all the
         * available input cannot be copied when flushing, try copying to the
         * window and the pending buffer instead. Also never write an empty
         * block when flushing: deflate() does that. */
        if len < min_block
            && ((len == 0 && flush != Z_FINISH)
                || flush == Z_NO_FLUSH
                || len != left + strm.avail_in)
        {
            break;
        }

        /* Make a dummy stored block in pending to get the header bytes,
         * including any pending bits. */
        last = flush == Z_FINISH && len == left + strm.avail_in;
        tr_stored_block(s, 0, 0, last);

        /* Replace the lengths in the dummy stored block with len. */
        s.pending_buf[s.pending - 4] = (len & 0xff) as u8;
        s.pending_buf[s.pending - 3] = ((len >> 8) & 0xff) as u8;
        let nlen = !(len as u32);
        s.pending_buf[s.pending - 2] = (nlen & 0xff) as u8;
        s.pending_buf[s.pending - 1] = ((nlen >> 8) & 0xff) as u8;

        /* Write the stored block header bytes. */
        flush_pending(strm, s);

        /* Copy uncompressed bytes from the window to next_out. */
        if left != 0 {
            if left > len {
                left = len;
            }
            let from = s.block_start as usize;
            let next_out = strm.next_out;
            strm.output[next_out..next_out + left].copy_from_slice(&s.window[from..from + left]);
            strm.next_out += left;
            strm.avail_out -= left;
            strm.total_out += left;
            s.block_start += left as isize;
            len -= left;
        }

        /* Copy uncompressed bytes directly from next_in to next_out, updating
         * the check value. */
        if len != 0 {
            let next_out = strm.next_out;
            read_buf_output(strm, s, next_out, len);
            strm.next_out += len;
            strm.avail_out -= len;
            strm.total_out += len;
        }

        if last {
            break;
        }
    }

    /* Update the sliding window with the last w_size bytes of the copied data,
     * or append all of it if less than w_size was copied. */
    used -= strm.avail_in; /* number of input bytes directly copied */
    if used != 0 {
        /* If any input was used then no unused input remains in the window,
         * so block_start == strstart. */
        if used >= s.w_size {
            /* supplant the previous history */
            s.matches = 2; /* clear hash */
            let from = strm.next_in - s.w_size;
            let w_size = s.w_size;
            s.window[..w_size].copy_from_slice(&strm.input[from..strm.next_in]);
            s.strstart = s.w_size;
            s.insert = s.strstart;
        } else {
            if s.window_size - s.strstart <= used {
                /* Slide the window down. */
                s.strstart -= s.w_size;
                let w_size = s.w_size;
                let strstart = s.strstart;
                s.window.copy_within(w_size..w_size + strstart, 0);
                if s.matches < 2 {
                    s.matches += 1; /* add a pending slide_hash() */
                }
                if s.insert > s.strstart {
                    s.insert = s.strstart;
                }
            }
            let from = strm.next_in - used;
            let strstart = s.strstart;
            s.window[strstart..strstart + used].copy_from_slice(&strm.input[from..strm.next_in]);
            s.strstart += used;
            s.insert += if used > s.w_size - s.insert {
                s.w_size - s.insert
            } else {
                used
            };
        }
        s.block_start = s.strstart as isize;
    }

    /* If the last block was written to next_out, then done. */
    if last {
        return BS_FINISH_DONE;
    }

    /* If flushing and all input has been consumed, then done. */
    if flush != Z_NO_FLUSH
        && flush != Z_FINISH
        && strm.avail_in == 0
        && s.strstart as isize == s.block_start
    {
        return BS_BLOCK_DONE;
    }

    /* Fill the window with any remaining input. */
    have = s.window_size - s.strstart;
    if strm.avail_in > have && s.block_start >= s.w_size as isize {
        /* Slide the window down. */
        s.block_start -= s.w_size as isize;
        s.strstart -= s.w_size;
        let w_size = s.w_size;
        let strstart = s.strstart;
        s.window.copy_within(w_size..w_size + strstart, 0);
        if s.matches < 2 {
            s.matches += 1; /* add a pending slide_hash() */
        }
        have += s.w_size; /* more space now */
        if s.insert > s.strstart {
            s.insert = s.strstart;
        }
    }
    if have > strm.avail_in {
        have = strm.avail_in;
    }
    if have != 0 {
        let strstart = s.strstart;
        read_buf_window(strm, s, strstart, have);
        s.strstart += have;
        s.insert += if have > s.w_size - s.insert {
            s.w_size - s.insert
        } else {
            have
        };
    }

    /* There was not enough avail_out to write a complete worthy or flushed
     * stored block to next_out. Write a stored block to pending instead, if
     * there is enough input for a worthy block, or if flushing and the
     * remaining input fits in the pending buffer. */
    have = (s.bi_valid + 42) >> 3;
    have = if s.pending_buf_size - have > MAX_STORED {
        MAX_STORED
    } else {
        s.pending_buf_size - have
    };
    min_block = if have > s.w_size { s.w_size } else { have };
    left = (s.strstart as isize - s.block_start) as usize;
    if left >= min_block
        || ((left != 0 || flush == Z_FINISH)
            && flush != Z_NO_FLUSH
            && strm.avail_in == 0
            && left <= have)
    {
        len = if left > have { have } else { left };
        last = flush == Z_FINISH && strm.avail_in == 0 && len == left;
        let block_start = s.block_start;
        tr_stored_block(s, block_start, len, last);
        s.block_start += len as isize;
        flush_pending(strm, s);
    }

    /* All that could be done with the available input and output is done. */
    if last {
        BS_FINISH_STARTED
    } else {
        BS_NEED_MORE
    }
}

/// Compress as much as possible from the input stream, without lazy match
/// evaluation. Used for the fast compression levels.
fn deflate_fast(strm: &mut ZStream, s: &mut DeflateState, flush: i32) -> i32 {
    let mut bflush;

    loop {
        /* Keep enough lookahead, except at the end of the input: MAX_MATCH
         * bytes for the next match plus MIN_MATCH to insert the string
         * following it. */
        if s.lookahead < MIN_LOOKAHEAD {
            fill_window(strm, s);
            if s.lookahead < MIN_LOOKAHEAD && flush == Z_NO_FLUSH {
                return BS_NEED_MORE;
            }
            if s.lookahead == 0 {
                break; /* flush the current block */
            }
        }

        /* Insert window[strstart .. strstart+2] in the dictionary and set
         * hash_head to the head of its hash chain. */
        let mut hash_head = 0usize;
        if s.lookahead >= MIN_MATCH {
            let strstart = s.strstart;
            hash_head = insert_string(s, strstart);
        }

        /* Find the longest match, discarding those <= prev_length. At this
         * point match_length < MIN_MATCH always holds. */
        if hash_head != 0 && s.strstart - hash_head <= s.w_size - MIN_LOOKAHEAD {
            /* Matches with the string at window index 0 are prevented, which
             * also avoids matching the string with itself at the start of the
             * input. */
            s.match_length = longest_match(s, hash_head);
        }

        if s.match_length >= MIN_MATCH {
            let dist = s.strstart - s.match_start;
            let lc = s.match_length - MIN_MATCH;
            bflush = tr_tally(s, dist, lc);

            s.lookahead -= s.match_length;

            /* Insert new strings in the hash table only when the match is not
             * too long. That saves time but degrades compression. */
            if s.match_length <= s.max_lazy_match && s.lookahead >= MIN_MATCH {
                s.match_length -= 1; /* string at strstart already in table */
                loop {
                    s.strstart += 1;
                    let strstart = s.strstart;
                    insert_string(s, strstart);
                    /* strstart never exceeds WSIZE-MAX_MATCH, so MIN_MATCH
                     * bytes are always ahead. */
                    s.match_length -= 1;
                    if s.match_length == 0 {
                        break;
                    }
                }
                s.strstart += 1;
            } else {
                s.strstart += s.match_length;
                s.match_length = 0;
                if s.legacy_hash {
                    s.ins_h = win_byte(&s.window, s.strstart) as usize;
                    s.ins_h = ((s.ins_h << s.hash_shift)
                        ^ win_byte(&s.window, s.strstart + 1) as usize)
                        & s.hash_mask;
                    /* If lookahead < MIN_MATCH, ins_h is garbage, but it is
                     * recomputed at the next deflate call. */
                }
            }
        } else {
            /* No match: output a literal byte */
            let lit = s.window[s.strstart] as usize;
            bflush = tr_tally(s, 0, lit);
            s.lookahead -= 1;
            s.strstart += 1;
        }

        if bflush {
            flush_block_only(strm, s, false);
            if strm.avail_out == 0 {
                return BS_NEED_MORE;
            }
        }
    }

    s.insert = if s.strstart < MIN_MATCH - 1 {
        s.strstart
    } else {
        MIN_MATCH - 1
    };
    if flush == Z_FINISH {
        flush_block_only(strm, s, true);
        if strm.avail_out == 0 {
            return BS_FINISH_STARTED;
        }
        return BS_FINISH_DONE;
    }
    if s.sym_next != 0 {
        flush_block_only(strm, s, false);
        if strm.avail_out == 0 {
            return BS_NEED_MORE;
        }
    }
    BS_BLOCK_DONE
}

/// The same, but with lazy match evaluation: a match is adopted only when
/// there is no better one at the next window position.
fn deflate_slow(strm: &mut ZStream, s: &mut DeflateState, flush: i32) -> i32 {
    let mut bflush;

    loop {
        if s.lookahead < MIN_LOOKAHEAD {
            fill_window(strm, s);
            if s.lookahead < MIN_LOOKAHEAD && flush == Z_NO_FLUSH {
                return BS_NEED_MORE;
            }
            if s.lookahead == 0 {
                break; /* flush the current block */
            }
        }

        let mut hash_head = 0usize;
        if s.lookahead >= MIN_MATCH {
            let strstart = s.strstart;
            hash_head = insert_string(s, strstart);
        }

        /* Find the longest match, discarding those <= prev_length. */
        s.prev_length = s.match_length;
        s.prev_match = s.match_start;
        s.match_length = MIN_MATCH - 1;

        if hash_head != 0
            && s.prev_length < s.max_lazy_match
            && s.strstart - hash_head <= s.w_size - MIN_LOOKAHEAD
        {
            s.match_length = longest_match(s, hash_head);

            if s.match_length <= 5
                && (s.strategy == Z_FILTERED
                    || (s.match_length == MIN_MATCH && s.strstart - s.match_start > TOO_FAR))
            {
                /* If prev_match is also MIN_MATCH, match_start is garbage, but
                 * the current match is ignored anyway. */
                s.match_length = MIN_MATCH - 1;
            }
        }

        /* If there was a match at the previous step and the current one is not
         * better, output the previous match. */
        if s.prev_length >= MIN_MATCH && s.match_length <= s.prev_length {
            /* Do not insert strings in the hash table beyond this. */
            let max_insert = (s.strstart + s.lookahead) as isize - MIN_MATCH as isize;

            let dist = s.strstart - 1 - s.prev_match;
            let lc = s.prev_length - MIN_MATCH;
            bflush = tr_tally(s, dist, lc);

            /* Insert all strings up to the end of the match in the hash table.
             * strstart-1 and strstart are already inserted; with insufficient
             * lookahead the last two strings are not inserted. */
            s.lookahead -= s.prev_length - 1;
            s.prev_length -= 2;
            loop {
                s.strstart += 1;
                if s.strstart as isize <= max_insert {
                    let strstart = s.strstart;
                    insert_string(s, strstart);
                }
                s.prev_length -= 1;
                if s.prev_length == 0 {
                    break;
                }
            }
            s.match_available = false;
            s.match_length = MIN_MATCH - 1;
            s.strstart += 1;

            if bflush {
                flush_block_only(strm, s, false);
                if strm.avail_out == 0 {
                    return BS_NEED_MORE;
                }
            }
        } else if s.match_available {
            /* If there was no match at the previous position, output a single
             * literal. If there was a match but the current one is longer,
             * truncate the previous match to a single literal. */
            let lit = s.window[s.strstart - 1] as usize;
            bflush = tr_tally(s, 0, lit);

            if bflush {
                flush_block_only(strm, s, false);
            }
            s.strstart += 1;
            s.lookahead -= 1;
            if strm.avail_out == 0 {
                return BS_NEED_MORE;
            }
        } else {
            /* No previous match to compare with: wait for the next step. */
            s.match_available = true;
            s.strstart += 1;
            s.lookahead -= 1;
        }
    }

    if s.match_available {
        let lit = s.window[s.strstart - 1] as usize;
        tr_tally(s, 0, lit);
        s.match_available = false;
    }
    s.insert = if s.strstart < MIN_MATCH - 1 {
        s.strstart
    } else {
        MIN_MATCH - 1
    };
    if flush == Z_FINISH {
        flush_block_only(strm, s, true);
        if strm.avail_out == 0 {
            return BS_FINISH_STARTED;
        }
        return BS_FINISH_DONE;
    }
    if s.sym_next != 0 {
        flush_block_only(strm, s, false);
        if strm.avail_out == 0 {
            return BS_NEED_MORE;
        }
    }

    BS_BLOCK_DONE
}

/// For `Z_RLE`: look only for runs of bytes, generating matches at distance
/// one, and maintain no hash table.
fn deflate_rle(strm: &mut ZStream, s: &mut DeflateState, flush: i32) -> i32 {
    let mut bflush;

    loop {
        /* Keep MAX_MATCH bytes of lookahead for the longest run, plus one for
         * the unrolled loop. */
        if s.lookahead <= MAX_MATCH {
            fill_window(strm, s);
            if s.lookahead <= MAX_MATCH && flush == Z_NO_FLUSH {
                return BS_NEED_MORE;
            }
            if s.lookahead == 0 {
                break; /* flush the current block */
            }
        }

        /* See how many times the previous byte repeats */
        s.match_length = 0;
        if s.lookahead >= MIN_MATCH && s.strstart > 0 {
            let win = &s.window;
            let mut scan = s.strstart - 1;
            let prev = win.get(scan).copied();
            let three = {
                let a = {
                    scan += 1;
                    win.get(scan).copied() == prev
                };
                let b = a && {
                    scan += 1;
                    win.get(scan).copied() == prev
                };
                b && {
                    scan += 1;
                    win.get(scan).copied() == prev
                }
            };
            if three {
                let strend = s.strstart + MAX_MATCH;
                loop {
                    let mut matched = true;
                    for _ in 0..8 {
                        scan += 1;
                        if win.get(scan).copied() != prev {
                            matched = false;
                            break;
                        }
                    }
                    if !matched || scan >= strend {
                        break;
                    }
                }
                s.match_length = MAX_MATCH - (strend - scan);
                if s.match_length > s.lookahead {
                    s.match_length = s.lookahead;
                }
            }
        }

        /* Emit a match for a run of MIN_MATCH or longer, else a literal */
        if s.match_length >= MIN_MATCH {
            let lc = s.match_length - MIN_MATCH;
            bflush = tr_tally(s, 1, lc);

            s.lookahead -= s.match_length;
            s.strstart += s.match_length;
            s.match_length = 0;
        } else {
            let lit = s.window[s.strstart] as usize;
            bflush = tr_tally(s, 0, lit);
            s.lookahead -= 1;
            s.strstart += 1;
        }

        if bflush {
            flush_block_only(strm, s, false);
            if strm.avail_out == 0 {
                return BS_NEED_MORE;
            }
        }
    }

    s.insert = 0;
    if flush == Z_FINISH {
        flush_block_only(strm, s, true);
        if strm.avail_out == 0 {
            return BS_FINISH_STARTED;
        }
        return BS_FINISH_DONE;
    }
    if s.sym_next != 0 {
        flush_block_only(strm, s, false);
        if strm.avail_out == 0 {
            return BS_NEED_MORE;
        }
    }
    BS_BLOCK_DONE
}

/// For `Z_HUFFMAN_ONLY`: do not look for matches at all, and maintain no hash
/// table.
fn deflate_huff(strm: &mut ZStream, s: &mut DeflateState, flush: i32) -> i32 {
    let mut bflush;

    loop {
        /* Make sure there is a literal to write. */
        if s.lookahead == 0 {
            fill_window(strm, s);
            if s.lookahead == 0 {
                if flush == Z_NO_FLUSH {
                    return BS_NEED_MORE;
                }
                break; /* flush the current block */
            }
        }

        s.match_length = 0;
        let lit = s.window[s.strstart] as usize;
        bflush = tr_tally(s, 0, lit);
        s.lookahead -= 1;
        s.strstart += 1;

        if bflush {
            flush_block_only(strm, s, false);
            if strm.avail_out == 0 {
                return BS_NEED_MORE;
            }
        }
    }

    s.insert = 0;
    if flush == Z_FINISH {
        flush_block_only(strm, s, true);
        if strm.avail_out == 0 {
            return BS_FINISH_STARTED;
        }
        return BS_FINISH_DONE;
    }
    if s.sym_next != 0 {
        flush_block_only(strm, s, false);
        if strm.avail_out == 0 {
            return BS_NEED_MORE;
        }
    }
    BS_BLOCK_DONE
}

/// Initialize the "longest match" routines for a new zlib stream.
fn lm_init(s: &mut DeflateState) {
    s.window_size = 2 * s.w_size;

    s.head.iter_mut().for_each(|h| *h = 0); /* fill with NIL */

    let cfg = CONFIGURATION_TABLE[s.level as usize];
    s.max_lazy_match = cfg.max_lazy as usize;
    s.good_match = cfg.good_length as usize;
    s.nice_match = cfg.nice_length as usize;
    s.max_chain_length = cfg.max_chain as usize;

    s.strstart = 0;
    s.block_start = 0;
    s.lookahead = 0;
    s.insert = 0;
    s.match_length = MIN_MATCH - 1;
    s.prev_length = MIN_MATCH - 1;
    s.match_available = false;
    s.ins_h = 0;
}

/// Check for a valid deflate stream state.
///
/// zlib also verifies that `strm.state` points back at `strm`; that pairing
/// cannot be broken here because the state is passed as its own argument, so
/// only the status check survives.
fn state_check(s: &DeflateState) -> bool {
    s.status != INIT_STATE
        && s.status != GZIP_STATE
        && s.status != EXTRA_STATE
        && s.status != NAME_STATE
        && s.status != COMMENT_STATE
        && s.status != HCRC_STATE
        && s.status != BUSY_STATE
        && s.status != FINISH_STATE
}

pub fn deflate_reset_keep(strm: &mut ZStream, s: &mut DeflateState) -> i32 {
    if state_check(s) {
        return err(strm, Z_STREAM_ERROR);
    }

    strm.total_in = 0;
    strm.total_out = 0;
    strm.data_type = Z_UNKNOWN;

    s.pending = 0;
    s.pending_out = 0;

    if s.wrap < 0 {
        /* was made negative by deflate(..., Z_FINISH) */
        s.wrap = -s.wrap;
    }
    s.status = if s.wrap == 2 {
        GZIP_STATE
    } else if s.wrap != 0 {
        INIT_STATE
    } else {
        BUSY_STATE
    };
    strm.adler = if s.wrap == 2 { 0 } else { 1 };
    s.last_flush = -2;
    tr_init(s);
    Z_OK
}

pub fn deflate_reset(strm: &mut ZStream, s: &mut DeflateState) -> i32 {
    let ret = deflate_reset_keep(strm, s);
    if ret == Z_OK {
        lm_init(s);
    }
    ret
}

pub fn deflate_set_header(s: &mut DeflateState, head: GzHeader) -> i32 {
    if state_check(s) || s.wrap != 2 {
        return Z_STREAM_ERROR;
    }
    s.gzhead = Some(head);
    Z_OK
}

#[allow(clippy::too_many_arguments)]
pub fn deflate_init2(
    strm: &mut ZStream,
    s: &mut DeflateState,
    level: i32,
    method: i32,
    window_bits: i32,
    mem_level: i32,
    strategy: i32,
    legacy_hash: bool,
) -> i32 {
    let mut level = level;
    let mut window_bits = window_bits;
    let mut wrap = 1;

    if level == Z_DEFAULT_COMPRESSION {
        level = 6;
    }

    if window_bits < 0 {
        /* suppress zlib wrapper */
        wrap = 0;
        window_bits = -window_bits;
    } else if window_bits > 15 {
        /* write a gzip wrapper instead */
        wrap = 2;
        window_bits -= 16;
    }

    if !(1..=MAX_MEM_LEVEL).contains(&mem_level)
        || method != Z_DEFLATED
        || !(8..=15).contains(&window_bits)
        || !(0..=9).contains(&level)
        || !(0..=Z_FIXED).contains(&strategy)
        || (window_bits == 8 && wrap != 1)
    {
        return err(strm, Z_STREAM_ERROR);
    }

    if window_bits == 8 {
        /* until the 256-byte window bug is fixed */
        window_bits = 9;
    }

    s.status = INIT_STATE; /* to pass the state test in deflate_reset */

    s.wrap = wrap;
    s.gzhead = None;
    s.w_bits = window_bits;
    s.w_size = 1usize << s.w_bits;
    s.w_mask = s.w_size - 1;

    s.legacy_hash = legacy_hash;

    s.hash_bits = mem_level as usize + 7;
    /* The ANZAC++ hash needs >= 15 hash bits to span the four bytes it reads. */
    if !s.legacy_hash && s.hash_bits < 15 {
        s.hash_bits = 15;
    }
    s.hash_size = 1usize << s.hash_bits;
    s.hash_mask = s.hash_size - 1;
    s.hash_shift = s.hash_bits.div_ceil(MIN_MATCH);

    s.window = vec![0u8; s.w_size * 2];
    s.head = vec![0u16; s.hash_size];
    s.prev = vec![0u16; s.w_size];

    s.lit_bufsize = 1usize << (mem_level + 6); /* 16K elements by default */

    /* pending_buf and sym_buf are overlaid, which works because the average
     * size of a length/distance pair over any compressed block is assured to
     * be 31 bits or less: sym_buf starts a quarter of the way into
     * pending_buf, giving three sym_buf bytes for every four pending_buf
     * bytes, so the compressed data cannot overtake the symbols it is being
     * built from. See the long analysis in the original. */
    s.pending_buf_size = s.lit_bufsize * 4;
    s.pending_buf = vec![0u8; s.pending_buf_size];

    /* Offset from the start of pending_buf rather than a pointer into it. */
    s.sym_buf = s.lit_bufsize;

    /* Equality with lit_bufsize*3 is avoided because of 64K wraparound on
     * 16-bit machines and because stored blocks are limited to 64K-1 bytes. */
    s.sym_end = (s.lit_bufsize - 1) * 3;

    s.level = level;
    s.strategy = strategy;
    s.method = method;

    deflate_reset(strm, s)
}

pub fn deflate_init(strm: &mut ZStream, s: &mut DeflateState, level: i32) -> i32 {
    deflate_init2(
        strm,
        s,
        level,
        Z_DEFLATED,
        MAX_WBITS,
        super::deflate_state::DEF_MEM_LEVEL,
        super::constants::Z_DEFAULT_STRATEGY,
        false,
    )
}

/// Compress as much input as possible and write as much output as fits.
pub fn deflate(strm: &mut ZStream, s: &mut DeflateState, flush: i32) -> i32 {
    if state_check(s) || !(0..=Z_BLOCK).contains(&flush) {
        return err(strm, Z_STREAM_ERROR);
    }

    if strm.output.is_empty()
        || (strm.avail_in != 0 && strm.input.is_empty())
        || (s.status == FINISH_STATE && flush != Z_FINISH)
    {
        let code = if strm.avail_out == 0 {
            Z_BUF_ERROR
        } else {
            Z_STREAM_ERROR
        };
        return err(strm, code);
    }

    let old_flush = s.last_flush;
    s.last_flush = flush;

    /* Flush as much pending output as possible */
    if s.pending != 0 {
        flush_pending(strm, s);
        if strm.avail_out == 0 {
            /* Since avail_out is 0, deflate will be called again with more
             * output space, but possibly with both pending and avail_in zero.
             * There will be nothing to do, but that is not an error, so make
             * sure the next call returns OK rather than BUF_ERROR. */
            s.last_flush = -1;
            return Z_OK;
        }
    } else if strm.avail_in == 0 && rank(flush) <= rank(old_flush) && flush != Z_FINISH {
        /* Make sure there is something to do and avoid duplicate consecutive
         * flushes. Repeated useless calls with Z_FINISH keep returning
         * Z_STREAM_END rather than Z_BUF_ERROR. */
        return err(strm, Z_BUF_ERROR);
    }

    /* The caller must not provide more input after the first FINISH */
    if s.status == FINISH_STATE && strm.avail_in != 0 {
        return err(strm, Z_BUF_ERROR);
    }

    /* Write the header */
    if s.status == INIT_STATE && s.wrap == 0 {
        s.status = BUSY_STATE;
    }
    if s.status == INIT_STATE {
        /* zlib header */
        let mut header = ((Z_DEFLATED + ((s.w_bits - 8) << 4)) << 8) as u32;
        let level_flags: u32 = if s.strategy >= Z_HUFFMAN_ONLY || s.level < 2 {
            0
        } else if s.level < 6 {
            1
        } else if s.level == 6 {
            2
        } else {
            3
        };
        header |= level_flags << 6;
        if s.strstart != 0 {
            header |= PRESET_DICT as u32;
        }
        header += 31 - (header % 31);

        put_short_msb(s, header);

        /* Save the adler32 of the preset dictionary */
        if s.strstart != 0 {
            let adler = strm.adler;
            put_short_msb(s, adler >> 16);
            put_short_msb(s, adler & 0xffff);
        }
        strm.adler = 1;
        s.status = BUSY_STATE;

        /* Compression must start with an empty pending buffer */
        flush_pending(strm, s);
        if s.pending != 0 {
            s.last_flush = -1;
            return Z_OK;
        }
    }

    if s.status == GZIP_STATE {
        /* gzip header */
        strm.adler = 0;
        put_byte(s, 31);
        put_byte(s, 139);
        put_byte(s, 8);
        let xfl = if s.level == 9 {
            2
        } else if s.strategy >= Z_HUFFMAN_ONLY || s.level < 2 {
            4
        } else {
            0
        };
        match s.gzhead.clone() {
            None => {
                put_byte(s, 0);
                put_byte(s, 0);
                put_byte(s, 0);
                put_byte(s, 0);
                put_byte(s, 0);
                put_byte(s, xfl);
                put_byte(s, OS_CODE as u8);
                s.status = BUSY_STATE;

                /* Compression must start with an empty pending buffer */
                flush_pending(strm, s);
                if s.pending != 0 {
                    s.last_flush = -1;
                    return Z_OK;
                }
            }
            Some(head) => {
                // The flag bits follow the original's truthiness tests: an
                // absent extra field is null, while a name or comment that is
                // the empty string is falsy and so reports absent too.
                let has_extra = head.extra.is_some();
                let has_name = head.name.as_ref().is_some_and(|n| !n.is_empty());
                let has_comment = head.comment.as_ref().is_some_and(|c| !c.is_empty());
                put_byte(
                    s,
                    (if head.text != 0 { 1 } else { 0 })
                        + (if head.hcrc != 0 { 2 } else { 0 })
                        + (if has_extra { 4 } else { 0 })
                        + (if has_name { 8 } else { 0 })
                        + (if has_comment { 16 } else { 0 }),
                );
                put_byte(s, (head.time & 0xff) as u8);
                put_byte(s, ((head.time >> 8) & 0xff) as u8);
                put_byte(s, ((head.time >> 16) & 0xff) as u8);
                put_byte(s, ((head.time >> 24) & 0xff) as u8);
                put_byte(s, xfl);
                put_byte(s, (head.os & 0xff) as u8);
                if let Some(extra) = head.extra.as_ref() {
                    if !extra.is_empty() {
                        put_byte(s, (extra.len() & 0xff) as u8);
                        put_byte(s, ((extra.len() >> 8) & 0xff) as u8);
                    }
                }
                if head.hcrc != 0 {
                    strm.adler = crc32(strm.adler, &s.pending_buf, s.pending, 0);
                }
                s.gzindex = 0;
                s.status = EXTRA_STATE;
            }
        }
    }

    if s.status == EXTRA_STATE {
        let hcrc = s.gzhead.as_ref().map(|h| h.hcrc != 0).unwrap_or(false);
        if let Some(extra) = s.gzhead.as_ref().and_then(|h| h.extra.clone()) {
            let mut beg = s.pending; /* start of bytes to update the crc */
            let mut left = (extra.len() & 0xffff) - s.gzindex;
            while s.pending + left > s.pending_buf_size {
                let copy = s.pending_buf_size - s.pending;
                let pending = s.pending;
                s.pending_buf[pending..pending + copy]
                    .copy_from_slice(&extra[s.gzindex..s.gzindex + copy]);
                s.pending = s.pending_buf_size;
                if hcrc && s.pending > beg {
                    strm.adler = crc32(strm.adler, &s.pending_buf, s.pending - beg, beg);
                }
                s.gzindex += copy;
                flush_pending(strm, s);
                if s.pending != 0 {
                    s.last_flush = -1;
                    return Z_OK;
                }
                beg = 0;
                left -= copy;
            }
            let pending = s.pending;
            s.pending_buf[pending..pending + left]
                .copy_from_slice(&extra[s.gzindex..s.gzindex + left]);
            s.pending += left;
            if hcrc && s.pending > beg {
                strm.adler = crc32(strm.adler, &s.pending_buf, s.pending - beg, beg);
            }
            s.gzindex = 0;
        }
        s.status = NAME_STATE;
    }

    if s.status == NAME_STATE {
        let hcrc = s.gzhead.as_ref().map(|h| h.hcrc != 0).unwrap_or(false);
        let name = s
            .gzhead
            .as_ref()
            .and_then(|h| h.name.clone())
            .filter(|n| !n.is_empty());
        if let Some(name) = name {
            let bytes: Vec<u8> = name.chars().map(|c| (c as u32 & 0xff) as u8).collect();
            let mut beg = s.pending;
            loop {
                if s.pending == s.pending_buf_size {
                    if hcrc && s.pending > beg {
                        strm.adler = crc32(strm.adler, &s.pending_buf, s.pending - beg, beg);
                    }
                    flush_pending(strm, s);
                    if s.pending != 0 {
                        s.last_flush = -1;
                        return Z_OK;
                    }
                    beg = 0;
                }
                // The original walks past the end of the string to append the
                // zero terminator, so an exhausted index yields 0.
                let val = if s.gzindex < bytes.len() {
                    let v = bytes[s.gzindex];
                    s.gzindex += 1;
                    v
                } else {
                    0
                };
                put_byte(s, val);
                if val == 0 {
                    break;
                }
            }
            if hcrc && s.pending > beg {
                strm.adler = crc32(strm.adler, &s.pending_buf, s.pending - beg, beg);
            }
            s.gzindex = 0;
        }
        s.status = COMMENT_STATE;
    }

    if s.status == COMMENT_STATE {
        let hcrc = s.gzhead.as_ref().map(|h| h.hcrc != 0).unwrap_or(false);
        let comment = s
            .gzhead
            .as_ref()
            .and_then(|h| h.comment.clone())
            .filter(|c| !c.is_empty());
        if let Some(comment) = comment {
            let bytes: Vec<u8> = comment.chars().map(|c| (c as u32 & 0xff) as u8).collect();
            let mut beg = s.pending;
            loop {
                if s.pending == s.pending_buf_size {
                    if hcrc && s.pending > beg {
                        strm.adler = crc32(strm.adler, &s.pending_buf, s.pending - beg, beg);
                    }
                    flush_pending(strm, s);
                    if s.pending != 0 {
                        s.last_flush = -1;
                        return Z_OK;
                    }
                    beg = 0;
                }
                let val = if s.gzindex < bytes.len() {
                    let v = bytes[s.gzindex];
                    s.gzindex += 1;
                    v
                } else {
                    0
                };
                put_byte(s, val);
                if val == 0 {
                    break;
                }
            }
            if hcrc && s.pending > beg {
                strm.adler = crc32(strm.adler, &s.pending_buf, s.pending - beg, beg);
            }
        }
        s.status = HCRC_STATE;
    }

    if s.status == HCRC_STATE {
        let hcrc = s.gzhead.as_ref().map(|h| h.hcrc != 0).unwrap_or(false);
        if hcrc {
            if s.pending + 2 > s.pending_buf_size {
                flush_pending(strm, s);
                if s.pending != 0 {
                    s.last_flush = -1;
                    return Z_OK;
                }
            }
            let adler = strm.adler;
            put_byte(s, (adler & 0xff) as u8);
            put_byte(s, ((adler >> 8) & 0xff) as u8);
            strm.adler = 0;
        }
        s.status = BUSY_STATE;

        /* Compression must start with an empty pending buffer */
        flush_pending(strm, s);
        if s.pending != 0 {
            s.last_flush = -1;
            return Z_OK;
        }
    }

    /* Start a new block or continue the current one. */
    if strm.avail_in != 0 || s.lookahead != 0 || (flush != Z_NO_FLUSH && s.status != FINISH_STATE) {
        let bstate = if s.level == 0 {
            deflate_stored(strm, s, flush)
        } else if s.strategy == Z_HUFFMAN_ONLY {
            deflate_huff(strm, s, flush)
        } else if s.strategy == Z_RLE {
            deflate_rle(strm, s, flush)
        } else if s.level < 4 {
            deflate_fast(strm, s, flush)
        } else {
            deflate_slow(strm, s, flush)
        };

        if bstate == BS_FINISH_STARTED || bstate == BS_FINISH_DONE {
            s.status = FINISH_STATE;
        }
        if bstate == BS_NEED_MORE || bstate == BS_FINISH_STARTED {
            if strm.avail_out == 0 {
                s.last_flush = -1; /* avoid BUF_ERROR on the next call */
            }
            /* With flush != Z_NO_FLUSH and avail_out == 0, the next deflate
             * call must use the same flush parameter so the flush completes,
             * so no empty block is written here. That also ensures at most one
             * empty block for a very small output buffer. */
            return Z_OK;
        }
        if bstate == BS_BLOCK_DONE {
            if flush == Z_PARTIAL_FLUSH {
                tr_align(s);
            } else if flush != Z_BLOCK {
                /* FULL_FLUSH or SYNC_FLUSH */
                tr_stored_block(s, 0, 0, false);
                /* For a full flush this empty block is recognized as a special
                 * marker by inflate_sync(). */
                if flush == Z_FULL_FLUSH {
                    s.head.iter_mut().for_each(|h| *h = 0); /* forget history */
                    if s.lookahead == 0 {
                        s.strstart = 0;
                        s.block_start = 0;
                        s.insert = 0;
                    }
                }
            }
            flush_pending(strm, s);
            if strm.avail_out == 0 {
                s.last_flush = -1; /* avoid BUF_ERROR on the next call */
                return Z_OK;
            }
        }
    }

    if flush != Z_FINISH {
        return Z_OK;
    }
    if s.wrap <= 0 {
        return Z_STREAM_END;
    }

    /* Write the trailer */
    if s.wrap == 2 {
        let adler = strm.adler;
        let total_in = strm.total_in as u32;
        put_byte(s, (adler & 0xff) as u8);
        put_byte(s, ((adler >> 8) & 0xff) as u8);
        put_byte(s, ((adler >> 16) & 0xff) as u8);
        put_byte(s, ((adler >> 24) & 0xff) as u8);
        put_byte(s, (total_in & 0xff) as u8);
        put_byte(s, ((total_in >> 8) & 0xff) as u8);
        put_byte(s, ((total_in >> 16) & 0xff) as u8);
        put_byte(s, ((total_in >> 24) & 0xff) as u8);
    } else {
        let adler = strm.adler;
        put_short_msb(s, adler >> 16);
        put_short_msb(s, adler & 0xffff);
    }

    flush_pending(strm, s);
    /* If avail_out is zero the application will call deflate again to flush
     * the rest. */
    if s.wrap > 0 {
        s.wrap = -s.wrap; /* write the trailer only once */
    }
    if s.pending != 0 {
        Z_OK
    } else {
        Z_STREAM_END
    }
}

pub fn deflate_end(strm: &mut ZStream, s: &mut DeflateState) -> i32 {
    if state_check(s) {
        return Z_STREAM_ERROR;
    }

    let status = s.status;
    if status == BUSY_STATE {
        err(strm, Z_DATA_ERROR)
    } else {
        Z_OK
    }
}

/// Initialize the compression dictionary from the given bytes without
/// producing any compressed output.
pub fn deflate_set_dictionary(strm: &mut ZStream, s: &mut DeflateState, dictionary: &[u8]) -> i32 {
    let mut dict_length = dictionary.len();

    if state_check(s) {
        return Z_STREAM_ERROR;
    }

    let wrap = s.wrap;

    if wrap == 2 || (wrap == 1 && s.status != INIT_STATE) || s.lookahead != 0 {
        return Z_STREAM_ERROR;
    }

    /* With a zlib wrapper, compute the Adler-32 of the dictionary */
    if wrap == 1 {
        strm.adler = adler32(strm.adler, dictionary, dict_length, 0);
    }

    s.wrap = 0; /* avoid computing Adler-32 in read_buf */

    /* If the dictionary would fill the window, just replace the history */
    let mut dict = dictionary.to_vec();
    if dict_length >= s.w_size {
        if wrap == 0 {
            /* already empty otherwise */
            s.head.iter_mut().for_each(|h| *h = 0);
            s.strstart = 0;
            s.block_start = 0;
            s.insert = 0;
        }
        /* use the tail */
        dict = dictionary[dict_length - s.w_size..].to_vec();
        dict_length = s.w_size;
    }

    /* Insert the dictionary into the window and the hash table by feeding it
     * through fill_window as if it were input. */
    let saved_avail = strm.avail_in;
    let saved_next = strm.next_in;
    let saved_input = std::mem::replace(&mut strm.input, dict);
    strm.avail_in = dict_length;
    strm.next_in = 0;

    fill_window(strm, s);
    while s.lookahead >= MIN_MATCH {
        let mut str_ = s.strstart;
        let mut n = s.lookahead - (MIN_MATCH - 1);
        loop {
            insert_string(s, str_);
            str_ += 1;
            n -= 1;
            if n == 0 {
                break;
            }
        }
        s.strstart = str_;
        s.lookahead = MIN_MATCH - 1;
        fill_window(strm, s);
    }
    s.strstart += s.lookahead;
    s.block_start = s.strstart as isize;
    s.insert = s.lookahead;
    s.lookahead = 0;
    s.match_length = MIN_MATCH - 1;
    s.prev_length = MIN_MATCH - 1;
    s.match_available = false;

    strm.input = saved_input;
    strm.next_in = saved_next;
    strm.avail_in = saved_avail;
    s.wrap = wrap;
    Z_OK
}
