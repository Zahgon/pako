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

//! The hot decode loop: literals, lengths and distances with no bounds checks.

use super::inflate_state::{fixed_distfix, fixed_lenfix, InflateState, Tables, BAD, TYPE};
use super::zstream::ZStream;

/// Decode literal, length, and distance codes and write out the resulting
/// literal and match bytes until either not enough input or output is
/// available, an end-of-block is encountered, or a data error is encountered.
///
/// When large enough input and output buffers are supplied to `inflate`, for
/// example a 16K input buffer and a 64K output buffer, more than 95% of the
/// inflate execution time is spent in this routine.
///
/// # Entry assumptions
///
/// The caller must guarantee all of these. They are what lets the loop run
/// without checking for input or output space on every symbol, and the index
/// arithmetic below will read or write out of range if any is violated:
///
/// - `state.mode == LEN`
/// - `strm.avail_in >= 6`
/// - `strm.avail_out >= 258`
/// - `start >= strm.avail_out`
/// - `state.bits < 8`
///
/// A length/distance pair costs at most 48 bits (15 code, 5 extra, 15 code,
/// 13 extra), hence six bytes of input; and emits at most 258 bytes, the
/// longest codeable match.
///
/// On return `state.mode` is one of `LEN` (ran out of input or output space),
/// `TYPE` (reached the end-of-block code) or `BAD` (error in block data).
pub fn inflate_fast(strm: &mut ZStream, state: &mut InflateState, start: usize) {
    // The tables and the window are moved out of the state for the duration
    // of the loop and moved back at the end. In C and in JavaScript these are
    // pointers read straight off the state while the same state is written;
    // Rust cannot hold those borrows across `state.mode = BAD`, and a Vec move
    // is a pointer swap rather than a copy, so this costs nothing.
    let lendyn = std::mem::take(&mut state.lendyn);
    let distdyn = std::mem::take(&mut state.distdyn);
    let s_window = std::mem::take(&mut state.window);

    let (lcode, dcode): (&[i32], &[i32]) = match state.active {
        Tables::Fixed => (fixed_lenfix(), fixed_distfix()),
        Tables::Dynamic => (&lendyn, &distdyn),
    };

    /* copy state to local variables */
    let input = &strm.input;
    let mut _in = strm.next_in;
    let last = _in + (strm.avail_in - 5);
    let output = &mut strm.output;
    let mut _out = strm.next_out;
    let beg = _out - (start - strm.avail_out);
    let end = _out + (strm.avail_out - 257);
    let dmax = state.dmax;
    let wsize = state.wsize;
    let whave = state.whave;
    let wnext = state.wnext;
    let mut hold = state.hold;
    let mut bits = state.bits;
    let lmask = (1u32 << state.lenbits) - 1;
    let dmask = (1u32 << state.distbits) - 1;

    let mut here: i32;
    let mut op: usize;
    let mut len: usize;
    let mut dist: usize;
    let mut from: usize;
    // Whether `from` indexes the sliding window or the output buffer. The
    // original reseats a single `from_source` variable between the two; the
    // two have different owners here, so the choice is carried as a flag and
    // branched on at the copy site.
    let mut from_window: bool;

    /* decode literals and length/distances until end-of-block or not enough
    input data or output space */
    'top: loop {
        if bits < 15 {
            hold = hold.wrapping_add((input[_in] as u32) << bits);
            _in += 1;
            bits += 8;
            hold = hold.wrapping_add((input[_in] as u32) << bits);
            _in += 1;
            bits += 8;
        }

        here = lcode[(hold & lmask) as usize];

        'dolen: loop {
            op = ((here as u32) >> 24) as usize;
            hold >>= op;
            bits -= op;
            op = (((here as u32) >> 16) & 0xff) as usize;

            if op == 0 {
                /* literal */
                output[_out] = (here & 0xffff) as u8;
                _out += 1;
            } else if op & 16 != 0 {
                /* length base */
                len = (here & 0xffff) as usize;
                op &= 15; /* number of extra bits */
                if op != 0 {
                    if bits < op {
                        hold = hold.wrapping_add((input[_in] as u32) << bits);
                        _in += 1;
                        bits += 8;
                    }
                    len += (hold & ((1 << op) - 1)) as usize;
                    hold >>= op;
                    bits -= op;
                }

                if bits < 15 {
                    hold = hold.wrapping_add((input[_in] as u32) << bits);
                    _in += 1;
                    bits += 8;
                    hold = hold.wrapping_add((input[_in] as u32) << bits);
                    _in += 1;
                    bits += 8;
                }

                here = dcode[(hold & dmask) as usize];

                'dodist: loop {
                    op = ((here as u32) >> 24) as usize;
                    hold >>= op;
                    bits -= op;
                    op = (((here as u32) >> 16) & 0xff) as usize;

                    if op & 16 != 0 {
                        /* distance base */
                        dist = (here & 0xffff) as usize;
                        op &= 15; /* number of extra bits */
                        if bits < op {
                            hold = hold.wrapping_add((input[_in] as u32) << bits);
                            _in += 1;
                            bits += 8;
                            if bits < op {
                                hold = hold.wrapping_add((input[_in] as u32) << bits);
                                _in += 1;
                                bits += 8;
                            }
                        }
                        dist += (hold & ((1 << op) - 1)) as usize;
                        if dist > dmax {
                            strm.msg = String::from("invalid distance too far back");
                            state.mode = BAD;
                            break 'top;
                        }
                        hold >>= op;
                        bits -= op;

                        op = _out - beg; /* max distance in output */
                        if dist > op {
                            /* see if copy from window */
                            op = dist - op; /* distance back in window */
                            if op > whave && state.sane {
                                strm.msg = String::from("invalid distance too far back");
                                state.mode = BAD;
                                break 'top;
                            }

                            // The INFLATE_ALLOW_INVALID_DISTANCE_TOOFAR_ARRR
                            // branch the original carries commented out is
                            // disabled in zlib's own defaults and is omitted
                            // here for the same binary-compatibility reason.

                            from = 0; // window index
                            from_window = true;
                            if wnext == 0 {
                                /* very common case */
                                from += wsize - op;
                                if op < len {
                                    /* some from window */
                                    len -= op;
                                    loop {
                                        output[_out] = s_window[from];
                                        _out += 1;
                                        from += 1;
                                        op -= 1;
                                        if op == 0 {
                                            break;
                                        }
                                    }
                                    from = _out - dist; /* rest from output */
                                    from_window = false;
                                }
                            } else if wnext < op {
                                /* wrap around window */
                                from += wsize + wnext - op;
                                op -= wnext;
                                if op < len {
                                    /* some from end of window */
                                    len -= op;
                                    loop {
                                        output[_out] = s_window[from];
                                        _out += 1;
                                        from += 1;
                                        op -= 1;
                                        if op == 0 {
                                            break;
                                        }
                                    }
                                    from = 0;
                                    if wnext < len {
                                        /* some from start of window */
                                        op = wnext;
                                        len -= op;
                                        loop {
                                            output[_out] = s_window[from];
                                            _out += 1;
                                            from += 1;
                                            op -= 1;
                                            if op == 0 {
                                                break;
                                            }
                                        }
                                        from = _out - dist; /* rest from output */
                                        from_window = false;
                                    }
                                }
                            } else {
                                /* contiguous in window */
                                from += wnext - op;
                                if op < len {
                                    /* some from window */
                                    len -= op;
                                    loop {
                                        output[_out] = s_window[from];
                                        _out += 1;
                                        from += 1;
                                        op -= 1;
                                        if op == 0 {
                                            break;
                                        }
                                    }
                                    from = _out - dist; /* rest from output */
                                    from_window = false;
                                }
                            }

                            if from_window {
                                while len > 2 {
                                    output[_out] = s_window[from];
                                    output[_out + 1] = s_window[from + 1];
                                    output[_out + 2] = s_window[from + 2];
                                    _out += 3;
                                    from += 3;
                                    len -= 3;
                                }
                                if len != 0 {
                                    output[_out] = s_window[from];
                                    _out += 1;
                                    from += 1;
                                    if len > 1 {
                                        output[_out] = s_window[from];
                                        _out += 1;
                                    }
                                }
                            } else {
                                while len > 2 {
                                    output[_out] = output[from];
                                    output[_out + 1] = output[from + 1];
                                    output[_out + 2] = output[from + 2];
                                    _out += 3;
                                    from += 3;
                                    len -= 3;
                                }
                                if len != 0 {
                                    output[_out] = output[from];
                                    _out += 1;
                                    from += 1;
                                    if len > 1 {
                                        output[_out] = output[from];
                                        _out += 1;
                                    }
                                }
                            }
                        } else {
                            from = _out - dist; /* copy direct from output */
                            // Byte at a time, and never `copy_within`: an
                            // overlapping LZ77 match has to re-read the bytes
                            // it just wrote, which is how a run shorter than
                            // `len` repeats to fill it.
                            loop {
                                /* minimum length is three */
                                output[_out] = output[from];
                                output[_out + 1] = output[from + 1];
                                output[_out + 2] = output[from + 2];
                                _out += 3;
                                from += 3;
                                len -= 3;
                                if len <= 2 {
                                    break;
                                }
                            }
                            if len != 0 {
                                output[_out] = output[from];
                                _out += 1;
                                from += 1;
                                if len > 1 {
                                    output[_out] = output[from];
                                    _out += 1;
                                }
                            }
                        }
                    } else if op & 64 == 0 {
                        /* 2nd level distance code */
                        here = dcode[(here & 0xffff) as usize + (hold & ((1 << op) - 1)) as usize];
                        continue 'dodist;
                    } else {
                        strm.msg = String::from("invalid distance code");
                        state.mode = BAD;
                        break 'top;
                    }

                    break 'dodist;
                }
            } else if op & 64 == 0 {
                /* 2nd level length code */
                here = lcode[(here & 0xffff) as usize + (hold & ((1 << op) - 1)) as usize];
                continue 'dolen;
            } else if op & 32 != 0 {
                /* end-of-block */
                state.mode = TYPE;
                break 'top;
            } else {
                strm.msg = String::from("invalid literal/length code");
                state.mode = BAD;
                break 'top;
            }

            break 'dolen;
        }

        if !(_in < last && _out < end) {
            break 'top;
        }
    }

    /* return unused bytes (on entry, bits < 8, so in won't go too far back) */
    len = bits >> 3;
    _in -= len;
    bits -= len << 3;
    hold &= (1 << bits) - 1;

    /* update state and return */
    strm.next_in = _in;
    strm.next_out = _out;
    strm.avail_in = if _in < last {
        5 + (last - _in)
    } else {
        5 - (_in - last)
    };
    strm.avail_out = if _out < end {
        257 + (end - _out)
    } else {
        257 - (_out - end)
    };
    state.hold = hold;
    state.bits = bits;

    state.lendyn = lendyn;
    state.distdyn = distdyn;
    state.window = s_window;
}
