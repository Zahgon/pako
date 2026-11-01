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

//! The inflate decoder: zlib, gzip and raw deflate streams.

use super::adler32::adler32;
use super::constants::{
    Z_BLOCK, Z_BUF_ERROR, Z_DATA_ERROR, Z_DEFLATED, Z_FINISH, Z_MEM_ERROR, Z_NEED_DICT, Z_OK,
    Z_STREAM_END, Z_STREAM_ERROR, Z_TREES,
};
use super::crc32::crc32;
use super::gzheader::GzHeader;
use super::inffast::inflate_fast;
use super::inflate_state::{
    zswap32, InflateState, Tables, BAD, CHECK, CODELENS, COMMENT, COPY, COPY_, DEF_WBITS, DICT,
    DICTID, DIST, DISTEXT, DONE, EXLEN, EXTRA, FLAGS, HCRC, HEAD, LEN, LENEXT, LENGTH, LENLENS,
    LEN_, LIT, MATCH, MEM, NAME, OS, STORED, SYNC, TABLE, TIME, TYPE, TYPEDO,
};
use super::inftrees::{inflate_table, CodeType};
use super::zstream::ZStream;

/// Permutation of code lengths, as the deflate format stores them.
const ORDER: [u8; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// The original's `inflateStateCheck`, reduced to the part that is observable.
///
/// zlib also verifies that `strm.state` points back at `strm`, guarding against
/// a stream whose state was freed or swapped. This API passes the state as its
/// own argument, so a mismatched pair cannot be constructed; only the mode
/// range check survives, and it still rejects a state that was never
/// initialised or was ended.
fn state_check(state: &InflateState) -> bool {
    state.mode < HEAD || state.mode > SYNC
}

pub fn inflate_reset_keep(strm: &mut ZStream, state: &mut InflateState) -> i32 {
    if state_check(state) {
        return Z_STREAM_ERROR;
    }
    strm.total_in = 0;
    strm.total_out = 0;
    state.total = 0;
    strm.msg = String::new();
    if state.wrap != 0 {
        /* to support ill-conceived Java test suite */
        strm.adler = (state.wrap & 1) as u32;
    }
    state.mode = HEAD;
    state.last = false;
    state.havedict = false;
    state.flags = -1;
    state.dmax = 32768;
    state.head = None;
    state.hold = 0;
    state.bits = 0;
    state.active = Tables::Dynamic;
    state.lendyn = vec![0i32; super::inflate_state::ENOUGH_LENS];
    state.distdyn = vec![0i32; super::inflate_state::ENOUGH_DISTS];
    state.sane = true;
    state.back = -1;
    Z_OK
}

pub fn inflate_reset(strm: &mut ZStream, state: &mut InflateState) -> i32 {
    if state_check(state) {
        return Z_STREAM_ERROR;
    }
    state.wsize = 0;
    state.whave = 0;
    state.wnext = 0;
    inflate_reset_keep(strm, state)
}

pub fn inflate_reset2(strm: &mut ZStream, state: &mut InflateState, window_bits: i32) -> i32 {
    let wrap;
    let mut window_bits = window_bits;

    if state_check(state) {
        return Z_STREAM_ERROR;
    }

    /* extract wrap request from windowBits parameter */
    if window_bits < 0 {
        wrap = 0;
        window_bits = -window_bits;
    } else {
        wrap = (window_bits >> 4) + 5;
        if window_bits < 48 {
            window_bits &= 15;
        }
    }

    /* set number of window bits, free window if different */
    if window_bits != 0 && !(8..=15).contains(&window_bits) {
        return Z_STREAM_ERROR;
    }
    if !state.window.is_empty() && state.wbits != window_bits {
        state.window = Vec::new();
    }

    state.wrap = wrap;
    state.wbits = window_bits;
    inflate_reset(strm, state)
}

pub fn inflate_init2(strm: &mut ZStream, state: &mut InflateState, window_bits: i32) -> i32 {
    state.window = Vec::new();
    state.mode = HEAD; /* to pass state test in inflate_reset2 */
    inflate_reset2(strm, state, window_bits)
}

pub fn inflate_init(strm: &mut ZStream, state: &mut InflateState) -> i32 {
    inflate_init2(strm, state, DEF_WBITS)
}

/// Update the window with the last `wsize` (normally 32K) bytes written before
/// returning. If the window does not exist yet, create it.
///
/// Called when a window is already in use, when output was written during this
/// inflate call but the deflate stream has not ended, and to seed the window
/// from a dictionary.
fn updatewindow(state: &mut InflateState, src: &[u8], end: usize, copy: usize) -> i32 {
    let mut copy = copy;

    if state.window.is_empty() {
        state.window = vec![0u8; 1usize << state.wbits];
    }

    if state.wsize == 0 {
        state.wsize = 1usize << state.wbits;
        state.wnext = 0;
        state.whave = 0;
    }

    if copy >= state.wsize {
        let from = end - state.wsize;
        state.window[..state.wsize].copy_from_slice(&src[from..end]);
        state.wnext = 0;
        state.whave = state.wsize;
    } else {
        let mut dist = state.wsize - state.wnext;
        if dist > copy {
            dist = copy;
        }
        let from = end - copy;
        let wnext = state.wnext;
        state.window[wnext..wnext + dist].copy_from_slice(&src[from..from + dist]);
        copy -= dist;
        if copy != 0 {
            let from = end - copy;
            state.window[..copy].copy_from_slice(&src[from..end]);
            state.wnext = copy;
            state.whave = state.wsize;
        } else {
            state.wnext += dist;
            if state.wnext == state.wsize {
                state.wnext = 0;
            }
            if state.whave < state.wsize {
                state.whave += dist;
            }
        }
    }
    0
}

/// Decompress as much as possible, and stop when the input buffer becomes
/// empty or the output buffer becomes full.
///
/// The original emulates zlib's `goto inf_leave` with a labelled `break` out
/// of a `switch` inside a `for(;;)`. Rust's `match` has no fall-through, but
/// every fall-through in the original is preceded by assigning the very mode
/// it falls into, so `continue 'inf_leave` re-dispatches to the same arm and
/// the behaviour is identical. A plain `break` out of the original's `switch`
/// is likewise `continue 'inf_leave`, and `break inf_leave` is
/// `break 'inf_leave`.
pub fn inflate(strm: &mut ZStream, state: &mut InflateState, flush: i32) -> i32 {
    let mut put: usize;
    let mut next: usize;
    let mut have: usize;
    let mut left: usize;
    let mut hold: u32;
    let mut bits: usize;
    let mut _in: usize;
    let mut _out: usize;
    let mut copy: usize;
    let mut from: usize;
    let mut here: i32;
    let mut here_bits: usize;
    let mut here_op: usize;
    let mut here_val: usize;
    let mut last_bits: usize;
    let mut last_op: usize;
    let mut last_val: usize;
    let mut len: usize;
    let mut ret: i32;
    let mut hbuf = [0u8; 4];
    let mut n: usize;

    if state_check(state) || strm.output.is_empty() && strm.avail_out != 0 {
        return Z_STREAM_ERROR;
    }

    if state.mode == TYPE {
        state.mode = TYPEDO; /* skip check */
    }

    /* LOAD() */
    put = strm.next_out;
    left = strm.avail_out;
    next = strm.next_in;
    have = strm.avail_in;
    hold = state.hold;
    bits = state.bits;

    _in = have;
    _out = left;
    ret = Z_OK;

    'inf_leave: loop {
        match state.mode {
            HEAD => {
                if state.wrap == 0 {
                    state.mode = TYPEDO;
                    continue 'inf_leave;
                }
                while bits < 16 {
                    if have == 0 {
                        break 'inf_leave;
                    }
                    have -= 1;
                    hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                    next += 1;
                    bits += 8;
                }
                if state.wrap & 2 != 0 && hold == 0x8b1f {
                    /* gzip header */
                    if state.wbits == 0 {
                        state.wbits = 15;
                    }
                    state.check = 0;
                    hbuf[0] = (hold & 0xff) as u8;
                    hbuf[1] = ((hold >> 8) & 0xff) as u8;
                    state.check = crc32(state.check, &hbuf, 2, 0);
                    hold = 0;
                    bits = 0;
                    state.mode = FLAGS;
                    continue 'inf_leave;
                }
                if let Some(head) = state.head.as_mut() {
                    head.done = false;
                }
                if state.wrap & 1 == 0 || (((hold & 0xff) << 8).wrapping_add(hold >> 8)) % 31 != 0 {
                    strm.msg = String::from("incorrect header check");
                    state.mode = BAD;
                    continue 'inf_leave;
                }
                if (hold & 0x0f) as i32 != Z_DEFLATED {
                    strm.msg = String::from("unknown compression method");
                    state.mode = BAD;
                    continue 'inf_leave;
                }
                hold >>= 4;
                bits -= 4;
                len = (hold & 0x0f) as usize + 8;
                if state.wbits == 0 {
                    state.wbits = len as i32;
                }
                if len > 15 || len > state.wbits as usize {
                    strm.msg = String::from("invalid window size");
                    state.mode = BAD;
                    continue 'inf_leave;
                }

                // pako patch, kept: force the requested windowBits so the
                // maximum window is used by default. zlib would use
                // `1 << len`, the size the stream header advertises.
                state.dmax = 1usize << state.wbits;

                state.flags = 0; /* indicate zlib header */
                state.check = 1;
                strm.adler = 1;
                state.mode = if hold & 0x200 != 0 { DICTID } else { TYPE };
                hold = 0;
                bits = 0;
                continue 'inf_leave;
            }
            FLAGS => {
                while bits < 16 {
                    if have == 0 {
                        break 'inf_leave;
                    }
                    have -= 1;
                    hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                    next += 1;
                    bits += 8;
                }
                state.flags = hold as i32;
                if state.flags & 0xff != Z_DEFLATED {
                    strm.msg = String::from("unknown compression method");
                    state.mode = BAD;
                    continue 'inf_leave;
                }
                if state.flags & 0xe000 != 0 {
                    strm.msg = String::from("unknown header flags set");
                    state.mode = BAD;
                    continue 'inf_leave;
                }
                if let Some(head) = state.head.as_mut() {
                    head.text = ((hold >> 8) & 1) as i32;
                }
                if state.flags & 0x0200 != 0 && state.wrap & 4 != 0 {
                    hbuf[0] = (hold & 0xff) as u8;
                    hbuf[1] = ((hold >> 8) & 0xff) as u8;
                    state.check = crc32(state.check, &hbuf, 2, 0);
                }
                hold = 0;
                bits = 0;
                state.mode = TIME;
                continue 'inf_leave;
            }
            TIME => {
                while bits < 32 {
                    if have == 0 {
                        break 'inf_leave;
                    }
                    have -= 1;
                    hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                    next += 1;
                    bits += 8;
                }
                if let Some(head) = state.head.as_mut() {
                    head.time = hold;
                }
                if state.flags & 0x0200 != 0 && state.wrap & 4 != 0 {
                    hbuf[0] = (hold & 0xff) as u8;
                    hbuf[1] = ((hold >> 8) & 0xff) as u8;
                    hbuf[2] = ((hold >> 16) & 0xff) as u8;
                    hbuf[3] = ((hold >> 24) & 0xff) as u8;
                    state.check = crc32(state.check, &hbuf, 4, 0);
                }
                hold = 0;
                bits = 0;
                state.mode = OS;
                continue 'inf_leave;
            }
            OS => {
                while bits < 16 {
                    if have == 0 {
                        break 'inf_leave;
                    }
                    have -= 1;
                    hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                    next += 1;
                    bits += 8;
                }
                if let Some(head) = state.head.as_mut() {
                    head.xflags = (hold & 0xff) as i32;
                    head.os = (hold >> 8) as i32;
                }
                if state.flags & 0x0200 != 0 && state.wrap & 4 != 0 {
                    hbuf[0] = (hold & 0xff) as u8;
                    hbuf[1] = ((hold >> 8) & 0xff) as u8;
                    state.check = crc32(state.check, &hbuf, 2, 0);
                }
                hold = 0;
                bits = 0;
                state.mode = EXLEN;
                continue 'inf_leave;
            }
            EXLEN => {
                if state.flags & 0x0400 != 0 {
                    while bits < 16 {
                        if have == 0 {
                            break 'inf_leave;
                        }
                        have -= 1;
                        hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                        next += 1;
                        bits += 8;
                    }
                    state.length = hold as usize;
                    if let Some(head) = state.head.as_mut() {
                        head.extra_len = hold as usize;
                    }
                    if state.flags & 0x0200 != 0 && state.wrap & 4 != 0 {
                        hbuf[0] = (hold & 0xff) as u8;
                        hbuf[1] = ((hold >> 8) & 0xff) as u8;
                        state.check = crc32(state.check, &hbuf, 2, 0);
                    }
                    hold = 0;
                    bits = 0;
                } else if let Some(head) = state.head.as_mut() {
                    head.extra = None;
                }
                state.mode = EXTRA;
                continue 'inf_leave;
            }
            EXTRA => {
                if state.flags & 0x0400 != 0 {
                    copy = state.length;
                    if copy > have {
                        copy = have;
                    }
                    if copy != 0 {
                        if let Some(head) = state.head.as_mut() {
                            len = head.extra_len - state.length;
                            let extra_len = head.extra_len;
                            let extra = head.extra.get_or_insert_with(|| vec![0u8; extra_len]);
                            // The extra field is limited to 65536 bytes by the
                            // format, so extra_len already bounds this write.
                            extra[len..len + copy].copy_from_slice(&strm.input[next..next + copy]);
                        }
                        if state.flags & 0x0200 != 0 && state.wrap & 4 != 0 {
                            state.check = crc32(state.check, &strm.input, copy, next);
                        }
                        have -= copy;
                        next += copy;
                        state.length -= copy;
                    }
                    if state.length != 0 {
                        break 'inf_leave;
                    }
                }
                state.length = 0;
                state.mode = NAME;
                continue 'inf_leave;
            }
            NAME => {
                if state.flags & 0x0800 != 0 {
                    if have == 0 {
                        break 'inf_leave;
                    }
                    copy = 0;
                    loop {
                        len = strm.input[next + copy] as usize;
                        copy += 1;
                        // A constant 65536 limit, as the original uses: no
                        // caller-supplied buffer to overrun here.
                        if state.length < 65536 && len != 0 {
                            if let Some(head) = state.head.as_mut() {
                                head.name
                                    .get_or_insert_with(String::new)
                                    .push(len as u8 as char);
                                state.length += 1;
                            }
                        }
                        if len == 0 || copy >= have {
                            break;
                        }
                    }

                    if state.flags & 0x0200 != 0 && state.wrap & 4 != 0 {
                        state.check = crc32(state.check, &strm.input, copy, next);
                    }
                    have -= copy;
                    next += copy;
                    if len != 0 {
                        break 'inf_leave;
                    }
                } else if let Some(head) = state.head.as_mut() {
                    head.name = None;
                }
                state.length = 0;
                state.mode = COMMENT;
                continue 'inf_leave;
            }
            COMMENT => {
                if state.flags & 0x1000 != 0 {
                    if have == 0 {
                        break 'inf_leave;
                    }
                    copy = 0;
                    loop {
                        len = strm.input[next + copy] as usize;
                        copy += 1;
                        if state.length < 65536 && len != 0 {
                            if let Some(head) = state.head.as_mut() {
                                head.comment
                                    .get_or_insert_with(String::new)
                                    .push(len as u8 as char);
                                state.length += 1;
                            }
                        }
                        if len == 0 || copy >= have {
                            break;
                        }
                    }
                    if state.flags & 0x0200 != 0 && state.wrap & 4 != 0 {
                        state.check = crc32(state.check, &strm.input, copy, next);
                    }
                    have -= copy;
                    next += copy;
                    if len != 0 {
                        break 'inf_leave;
                    }
                } else if let Some(head) = state.head.as_mut() {
                    head.comment = None;
                }
                state.mode = HCRC;
                continue 'inf_leave;
            }
            HCRC => {
                if state.flags & 0x0200 != 0 {
                    while bits < 16 {
                        if have == 0 {
                            break 'inf_leave;
                        }
                        have -= 1;
                        hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                        next += 1;
                        bits += 8;
                    }
                    if state.wrap & 4 != 0 && hold != (state.check & 0xffff) {
                        strm.msg = String::from("header crc mismatch");
                        state.mode = BAD;
                        continue 'inf_leave;
                    }
                    hold = 0;
                    bits = 0;
                }
                let flags = state.flags;
                if let Some(head) = state.head.as_mut() {
                    head.hcrc = (flags >> 9) & 1;
                    head.done = true;
                }
                state.check = 0;
                strm.adler = 0;
                state.mode = TYPE;
                continue 'inf_leave;
            }
            DICTID => {
                while bits < 32 {
                    if have == 0 {
                        break 'inf_leave;
                    }
                    have -= 1;
                    hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                    next += 1;
                    bits += 8;
                }
                state.check = zswap32(hold);
                strm.adler = state.check;
                hold = 0;
                bits = 0;
                state.mode = DICT;
                continue 'inf_leave;
            }
            DICT => {
                if !state.havedict {
                    /* RESTORE() */
                    strm.next_out = put;
                    strm.avail_out = left;
                    strm.next_in = next;
                    strm.avail_in = have;
                    state.hold = hold;
                    state.bits = bits;
                    return Z_NEED_DICT;
                }
                state.check = 1;
                strm.adler = 1;
                state.mode = TYPE;
                continue 'inf_leave;
            }
            TYPE => {
                if flush == Z_BLOCK || flush == Z_TREES {
                    break 'inf_leave;
                }
                state.mode = TYPEDO;
                continue 'inf_leave;
            }
            TYPEDO => {
                if state.last {
                    hold >>= bits & 7;
                    bits -= bits & 7;
                    state.mode = CHECK;
                    continue 'inf_leave;
                }
                while bits < 3 {
                    if have == 0 {
                        break 'inf_leave;
                    }
                    have -= 1;
                    hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                    next += 1;
                    bits += 8;
                }
                state.last = hold & 0x01 != 0;
                hold >>= 1;
                bits -= 1;

                match hold & 0x03 {
                    0 => {
                        /* stored block */
                        state.mode = STORED;
                    }
                    1 => {
                        /* fixed block */
                        state.use_fixed_tables();
                        state.mode = LEN_; /* decode codes */
                        if flush == Z_TREES {
                            hold >>= 2;
                            bits -= 2;
                            break 'inf_leave;
                        }
                    }
                    2 => {
                        /* dynamic block */
                        state.mode = TABLE;
                    }
                    _ => {
                        strm.msg = String::from("invalid block type");
                        state.mode = BAD;
                    }
                }
                hold >>= 2;
                bits -= 2;
                continue 'inf_leave;
            }
            STORED => {
                /* go to byte boundary */
                hold >>= bits & 7;
                bits -= bits & 7;
                while bits < 32 {
                    if have == 0 {
                        break 'inf_leave;
                    }
                    have -= 1;
                    hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                    next += 1;
                    bits += 8;
                }
                if (hold & 0xffff) != ((hold >> 16) ^ 0xffff) {
                    strm.msg = String::from("invalid stored block lengths");
                    state.mode = BAD;
                    continue 'inf_leave;
                }
                state.length = (hold & 0xffff) as usize;
                hold = 0;
                bits = 0;
                state.mode = COPY_;
                if flush == Z_TREES {
                    break 'inf_leave;
                }
                continue 'inf_leave;
            }
            COPY_ => {
                state.mode = COPY;
                continue 'inf_leave;
            }
            COPY => {
                copy = state.length;
                if copy != 0 {
                    if copy > have {
                        copy = have;
                    }
                    if copy > left {
                        copy = left;
                    }
                    if copy == 0 {
                        break 'inf_leave;
                    }
                    for i in 0..copy {
                        strm.output[put + i] = strm.input[next + i];
                    }
                    have -= copy;
                    next += copy;
                    left -= copy;
                    put += copy;
                    state.length -= copy;
                    continue 'inf_leave;
                }
                state.mode = TYPE;
                continue 'inf_leave;
            }
            TABLE => {
                while bits < 14 {
                    if have == 0 {
                        break 'inf_leave;
                    }
                    have -= 1;
                    hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                    next += 1;
                    bits += 8;
                }
                state.nlen = (hold & 0x1f) as usize + 257;
                hold >>= 5;
                bits -= 5;
                state.ndist = (hold & 0x1f) as usize + 1;
                hold >>= 5;
                bits -= 5;
                state.ncode = (hold & 0x0f) as usize + 4;
                hold >>= 4;
                bits -= 4;
                if state.nlen > 286 || state.ndist > 30 {
                    strm.msg = String::from("too many length or distance symbols");
                    state.mode = BAD;
                    continue 'inf_leave;
                }
                state.have = 0;
                state.mode = LENLENS;
                continue 'inf_leave;
            }
            LENLENS => {
                while state.have < state.ncode {
                    while bits < 3 {
                        if have == 0 {
                            break 'inf_leave;
                        }
                        have -= 1;
                        hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                        next += 1;
                        bits += 8;
                    }
                    state.lens[ORDER[state.have] as usize] = (hold & 0x07) as u16;
                    state.have += 1;
                    hold >>= 3;
                    bits -= 3;
                }
                while state.have < 19 {
                    state.lens[ORDER[state.have] as usize] = 0;
                    state.have += 1;
                }
                state.active = Tables::Dynamic;
                state.lenbits = 7;

                let r = inflate_table(
                    CodeType::Codes,
                    &state.lens,
                    0,
                    19,
                    &mut state.lendyn,
                    &mut state.work,
                    &mut state.lenbits,
                );

                if r != 0 {
                    strm.msg = String::from("invalid code lengths set");
                    state.mode = BAD;
                    continue 'inf_leave;
                }
                state.have = 0;
                state.mode = CODELENS;
                continue 'inf_leave;
            }
            CODELENS => {
                while state.have < state.nlen + state.ndist {
                    loop {
                        here = state.lencode()[(hold & ((1 << state.lenbits) - 1)) as usize];
                        here_bits = ((here as u32) >> 24) as usize;
                        here_op = (((here as u32) >> 16) & 0xff) as usize;
                        here_val = (here & 0xffff) as usize;

                        if here_bits <= bits {
                            break;
                        }
                        if have == 0 {
                            break 'inf_leave;
                        }
                        have -= 1;
                        hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                        next += 1;
                        bits += 8;
                    }
                    let _ = here_op;
                    if here_val < 16 {
                        hold >>= here_bits;
                        bits -= here_bits;
                        state.lens[state.have] = here_val as u16;
                        state.have += 1;
                    } else {
                        if here_val == 16 {
                            n = here_bits + 2;
                            while bits < n {
                                if have == 0 {
                                    break 'inf_leave;
                                }
                                have -= 1;
                                hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                                next += 1;
                                bits += 8;
                            }
                            hold >>= here_bits;
                            bits -= here_bits;
                            if state.have == 0 {
                                strm.msg = String::from("invalid bit length repeat");
                                state.mode = BAD;
                                break;
                            }
                            len = state.lens[state.have - 1] as usize;
                            copy = 3 + (hold & 0x03) as usize;
                            hold >>= 2;
                            bits -= 2;
                        } else if here_val == 17 {
                            n = here_bits + 3;
                            while bits < n {
                                if have == 0 {
                                    break 'inf_leave;
                                }
                                have -= 1;
                                hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                                next += 1;
                                bits += 8;
                            }
                            hold >>= here_bits;
                            bits -= here_bits;
                            len = 0;
                            copy = 3 + (hold & 0x07) as usize;
                            hold >>= 3;
                            bits -= 3;
                        } else {
                            n = here_bits + 7;
                            while bits < n {
                                if have == 0 {
                                    break 'inf_leave;
                                }
                                have -= 1;
                                hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                                next += 1;
                                bits += 8;
                            }
                            hold >>= here_bits;
                            bits -= here_bits;
                            len = 0;
                            copy = 11 + (hold & 0x7f) as usize;
                            hold >>= 7;
                            bits -= 7;
                        }
                        if state.have + copy > state.nlen + state.ndist {
                            strm.msg = String::from("invalid bit length repeat");
                            state.mode = BAD;
                            break;
                        }
                        while copy > 0 {
                            copy -= 1;
                            state.lens[state.have] = len as u16;
                            state.have += 1;
                        }
                    }
                }

                /* handle error breaks in while */
                if state.mode == BAD {
                    continue 'inf_leave;
                }

                /* check for end-of-block code (better have one) */
                if state.lens[256] == 0 {
                    strm.msg = String::from("invalid code -- missing end-of-block");
                    state.mode = BAD;
                    continue 'inf_leave;
                }

                /* build code tables -- note: do not change the lenbits or
                distbits values here (9 and 6) without reading the comments
                in inftrees.h concerning the ENOUGH constants, which depend
                on those values */
                state.lenbits = 9;
                let nlen = state.nlen;
                let r = inflate_table(
                    CodeType::Lens,
                    &state.lens,
                    0,
                    nlen,
                    &mut state.lendyn,
                    &mut state.work,
                    &mut state.lenbits,
                );
                if r != 0 {
                    strm.msg = String::from("invalid literal/lengths set");
                    state.mode = BAD;
                    continue 'inf_leave;
                }

                state.distbits = 6;
                let ndist = state.ndist;
                let r = inflate_table(
                    CodeType::Dists,
                    &state.lens,
                    nlen,
                    ndist,
                    &mut state.distdyn,
                    &mut state.work,
                    &mut state.distbits,
                );
                if r != 0 {
                    strm.msg = String::from("invalid distances set");
                    state.mode = BAD;
                    continue 'inf_leave;
                }
                state.mode = LEN_;
                if flush == Z_TREES {
                    break 'inf_leave;
                }
                continue 'inf_leave;
            }
            LEN_ => {
                state.mode = LEN;
                continue 'inf_leave;
            }
            LEN => {
                if have >= 6 && left >= 258 {
                    /* RESTORE() */
                    strm.next_out = put;
                    strm.avail_out = left;
                    strm.next_in = next;
                    strm.avail_in = have;
                    state.hold = hold;
                    state.bits = bits;

                    inflate_fast(strm, state, _out);

                    /* LOAD() */
                    put = strm.next_out;
                    left = strm.avail_out;
                    next = strm.next_in;
                    have = strm.avail_in;
                    hold = state.hold;
                    bits = state.bits;

                    if state.mode == TYPE {
                        state.back = -1;
                    }
                    continue 'inf_leave;
                }
                state.back = 0;
                loop {
                    here = state.lencode()[(hold & ((1 << state.lenbits) - 1)) as usize];
                    here_bits = ((here as u32) >> 24) as usize;
                    here_op = (((here as u32) >> 16) & 0xff) as usize;
                    here_val = (here & 0xffff) as usize;

                    if here_bits <= bits {
                        break;
                    }
                    if have == 0 {
                        break 'inf_leave;
                    }
                    have -= 1;
                    hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                    next += 1;
                    bits += 8;
                }
                if here_op != 0 && here_op & 0xf0 == 0 {
                    last_bits = here_bits;
                    last_op = here_op;
                    last_val = here_val;
                    loop {
                        let idx = last_val
                            + ((hold & ((1 << (last_bits + last_op)) - 1)) >> last_bits) as usize;
                        here = state.lencode()[idx];
                        here_bits = ((here as u32) >> 24) as usize;
                        here_op = (((here as u32) >> 16) & 0xff) as usize;
                        here_val = (here & 0xffff) as usize;

                        if last_bits + here_bits <= bits {
                            break;
                        }
                        if have == 0 {
                            break 'inf_leave;
                        }
                        have -= 1;
                        hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                        next += 1;
                        bits += 8;
                    }
                    hold >>= last_bits;
                    bits -= last_bits;
                    state.back += last_bits as i32;
                }
                hold >>= here_bits;
                bits -= here_bits;
                state.back += here_bits as i32;
                state.length = here_val;
                if here_op == 0 {
                    state.mode = LIT;
                    continue 'inf_leave;
                }
                if here_op & 32 != 0 {
                    state.back = -1;
                    state.mode = TYPE;
                    continue 'inf_leave;
                }
                if here_op & 64 != 0 {
                    strm.msg = String::from("invalid literal/length code");
                    state.mode = BAD;
                    continue 'inf_leave;
                }
                state.extra = here_op & 15;
                state.mode = LENEXT;
                continue 'inf_leave;
            }
            LENEXT => {
                if state.extra != 0 {
                    n = state.extra;
                    while bits < n {
                        if have == 0 {
                            break 'inf_leave;
                        }
                        have -= 1;
                        hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                        next += 1;
                        bits += 8;
                    }
                    state.length += (hold & ((1 << state.extra) - 1)) as usize;
                    hold >>= state.extra;
                    bits -= state.extra;
                    state.back += state.extra as i32;
                }
                state.was = state.length;
                state.mode = DIST;
                continue 'inf_leave;
            }
            DIST => {
                loop {
                    here = state.distcode()[(hold & ((1 << state.distbits) - 1)) as usize];
                    here_bits = ((here as u32) >> 24) as usize;
                    here_op = (((here as u32) >> 16) & 0xff) as usize;
                    here_val = (here & 0xffff) as usize;

                    if here_bits <= bits {
                        break;
                    }
                    if have == 0 {
                        break 'inf_leave;
                    }
                    have -= 1;
                    hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                    next += 1;
                    bits += 8;
                }
                if here_op & 0xf0 == 0 {
                    last_bits = here_bits;
                    last_op = here_op;
                    last_val = here_val;
                    loop {
                        let idx = last_val
                            + ((hold & ((1 << (last_bits + last_op)) - 1)) >> last_bits) as usize;
                        here = state.distcode()[idx];
                        here_bits = ((here as u32) >> 24) as usize;
                        here_op = (((here as u32) >> 16) & 0xff) as usize;
                        here_val = (here & 0xffff) as usize;

                        if last_bits + here_bits <= bits {
                            break;
                        }
                        if have == 0 {
                            break 'inf_leave;
                        }
                        have -= 1;
                        hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                        next += 1;
                        bits += 8;
                    }
                    hold >>= last_bits;
                    bits -= last_bits;
                    state.back += last_bits as i32;
                }
                hold >>= here_bits;
                bits -= here_bits;
                state.back += here_bits as i32;
                if here_op & 64 != 0 {
                    strm.msg = String::from("invalid distance code");
                    state.mode = BAD;
                    continue 'inf_leave;
                }
                state.offset = here_val;
                state.extra = here_op & 15;
                state.mode = DISTEXT;
                continue 'inf_leave;
            }
            DISTEXT => {
                if state.extra != 0 {
                    n = state.extra;
                    while bits < n {
                        if have == 0 {
                            break 'inf_leave;
                        }
                        have -= 1;
                        hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                        next += 1;
                        bits += 8;
                    }
                    state.offset += (hold & ((1 << state.extra) - 1)) as usize;
                    hold >>= state.extra;
                    bits -= state.extra;
                    state.back += state.extra as i32;
                }
                if state.offset > state.dmax {
                    strm.msg = String::from("invalid distance too far back");
                    state.mode = BAD;
                    continue 'inf_leave;
                }
                state.mode = MATCH;
                continue 'inf_leave;
            }
            MATCH => {
                if left == 0 {
                    break 'inf_leave;
                }
                copy = _out - left;
                // `from_window` replaces the original's `from_source`, which
                // is reseated between the window and the output buffer; the
                // two have different owners here.
                let from_window;
                if state.offset > copy {
                    /* copy from window */
                    copy = state.offset - copy;
                    if copy > state.whave && state.sane {
                        strm.msg = String::from("invalid distance too far back");
                        state.mode = BAD;
                        continue 'inf_leave;
                    }
                    if copy > state.wnext {
                        copy -= state.wnext;
                        from = state.wsize - copy;
                    } else {
                        from = state.wnext - copy;
                    }
                    if copy > state.length {
                        copy = state.length;
                    }
                    from_window = true;
                } else {
                    /* copy from output */
                    from = put - state.offset;
                    copy = state.length;
                    from_window = false;
                }
                if copy > left {
                    copy = left;
                }
                left -= copy;
                state.length -= copy;
                // Byte at a time: an overlapping match re-reads the bytes it
                // just wrote, which is how a short run fills a longer match.
                for _ in 0..copy {
                    strm.output[put] = if from_window {
                        state.window[from]
                    } else {
                        strm.output[from]
                    };
                    put += 1;
                    from += 1;
                }
                if state.length == 0 {
                    state.mode = LEN;
                }
                continue 'inf_leave;
            }
            LIT => {
                if left == 0 {
                    break 'inf_leave;
                }
                strm.output[put] = state.length as u8;
                put += 1;
                left -= 1;
                state.mode = LEN;
                continue 'inf_leave;
            }
            CHECK => {
                if state.wrap != 0 {
                    while bits < 32 {
                        if have == 0 {
                            break 'inf_leave;
                        }
                        have -= 1;
                        hold |= (strm.input[next] as u32) << bits;
                        next += 1;
                        bits += 8;
                    }
                    _out -= left;
                    strm.total_out += _out;
                    state.total += _out;
                    if state.wrap & 4 != 0 && _out != 0 {
                        let c = if state.flags != 0 {
                            crc32(state.check, &strm.output, _out, put - _out)
                        } else {
                            adler32(state.check, &strm.output, _out, put - _out)
                        };
                        state.check = c;
                        strm.adler = c;
                    }
                    _out = left;
                    let got = if state.flags != 0 {
                        hold
                    } else {
                        zswap32(hold)
                    };
                    if state.wrap & 4 != 0 && got != state.check {
                        strm.msg = String::from("incorrect data check");
                        state.mode = BAD;
                        continue 'inf_leave;
                    }
                    hold = 0;
                    bits = 0;
                }
                state.mode = LENGTH;
                continue 'inf_leave;
            }
            LENGTH => {
                if state.wrap != 0 && state.flags != 0 {
                    while bits < 32 {
                        if have == 0 {
                            break 'inf_leave;
                        }
                        have -= 1;
                        hold = hold.wrapping_add((strm.input[next] as u32) << bits);
                        next += 1;
                        bits += 8;
                    }
                    if state.wrap & 4 != 0 && hold != (state.total as u32) {
                        strm.msg = String::from("incorrect length check");
                        state.mode = BAD;
                        continue 'inf_leave;
                    }
                    hold = 0;
                    bits = 0;
                }
                state.mode = DONE;
                continue 'inf_leave;
            }
            DONE => {
                ret = Z_STREAM_END;
                break 'inf_leave;
            }
            BAD => {
                ret = Z_DATA_ERROR;
                break 'inf_leave;
            }
            MEM => return Z_MEM_ERROR,
            _ => return Z_STREAM_ERROR,
        }
    }

    /* RESTORE() */
    strm.next_out = put;
    strm.avail_out = left;
    strm.next_in = next;
    strm.avail_in = have;
    state.hold = hold;
    state.bits = bits;

    if state.wsize != 0
        || (_out != strm.avail_out && state.mode < BAD && (state.mode < CHECK || flush != Z_FINISH))
    {
        let end = strm.next_out;
        let copied = _out - strm.avail_out;
        // The window is moved out so `state` can be borrowed mutably while
        // the just-written output is read; a Vec move is a pointer swap.
        let output = std::mem::take(&mut strm.output);
        let r = updatewindow(state, &output, end, copied);
        strm.output = output;
        if r != 0 {
            state.mode = MEM;
            return Z_MEM_ERROR;
        }
    }
    _in -= strm.avail_in;
    _out -= strm.avail_out;
    strm.total_in += _in;
    strm.total_out += _out;
    state.total += _out;
    if state.wrap & 4 != 0 && _out != 0 {
        let start = strm.next_out - _out;
        let c = if state.flags != 0 {
            crc32(state.check, &strm.output, _out, start)
        } else {
            adler32(state.check, &strm.output, _out, start)
        };
        state.check = c;
        strm.adler = c;
    }
    strm.data_type = state.bits as i32
        + if state.last { 64 } else { 0 }
        + if state.mode == TYPE { 128 } else { 0 }
        + if state.mode == LEN_ || state.mode == COPY_ {
            256
        } else {
            0
        };
    if ((_in == 0 && _out == 0) || flush == Z_FINISH) && ret == Z_OK {
        ret = Z_BUF_ERROR;
    }
    ret
}

pub fn inflate_end(state: &mut InflateState) -> i32 {
    if state_check(state) {
        return Z_STREAM_ERROR;
    }
    state.window = Vec::new();
    Z_OK
}

pub fn inflate_get_header(state: &mut InflateState, head: GzHeader) -> i32 {
    if state_check(state) {
        return Z_STREAM_ERROR;
    }
    if state.wrap & 2 == 0 {
        return Z_STREAM_ERROR;
    }
    let mut head = head;
    head.done = false;
    state.head = Some(head);
    Z_OK
}

pub fn inflate_set_dictionary(state: &mut InflateState, dictionary: &[u8]) -> i32 {
    let dict_length = dictionary.len();

    if state_check(state) {
        return Z_STREAM_ERROR;
    }

    if state.wrap != 0 && state.mode != DICT {
        return Z_STREAM_ERROR;
    }

    /* check for correct dictionary identifier */
    if state.mode == DICT {
        let dictid = adler32(1, dictionary, dict_length, 0);
        if dictid != state.check {
            return Z_DATA_ERROR;
        }
    }

    /* copy dictionary to window using updatewindow(), which will amend the
    existing dictionary if appropriate */
    if updatewindow(state, dictionary, dict_length, dict_length) != 0 {
        state.mode = MEM;
        return Z_MEM_ERROR;
    }
    state.havedict = true;
    Z_OK
}
