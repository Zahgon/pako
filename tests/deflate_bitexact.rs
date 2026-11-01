//! Byte-for-byte equality with the JavaScript encoder.
//!
//! Every expected length and CRC-32 below was produced by running the original
//! `src/deflate.ts` over the same input with the same options. Compression is
//! only useful if it is bit-exact: two encoders can both produce valid deflate
//! streams that decode to the same bytes while disagreeing on every byte of
//! the stream itself, and this suite is what rules that out.

use std::path::Path;

use pako::zlib::crc32::crc32;
use pako::zlib::deflate::{deflate, deflate_init2};
use pako::zlib::deflate_state::DeflateState;
use pako::zlib::zstream::ZStream;
use pako::{Z_DEFAULT_COMPRESSION, Z_DEFAULT_STRATEGY, Z_DEFLATED, Z_FINISH, Z_OK, Z_STREAM_END};

/// The option set `Deflate`'s constructor applies, with the original's
/// defaults.
struct Options {
    level: i32,
    chunk_size: usize,
    window_bits: i32,
    mem_level: i32,
    strategy: i32,
    raw: bool,
    gzip: bool,
    legacy_hash: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            level: Z_DEFAULT_COMPRESSION,
            chunk_size: 16384,
            window_bits: 15,
            mem_level: 8,
            strategy: Z_DEFAULT_STRATEGY,
            raw: false,
            gzip: false,
            legacy_hash: false,
        }
    }
}

fn fixture(rel: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("test").join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// Compress `data` exactly as `new Deflate(opts).push(data, true)` does.
fn deflate_all(data: &[u8], opts: &Options) -> Vec<u8> {
    // The constructor folds raw and gzip into the sign and magnitude of
    // windowBits before deflateInit2 ever sees them.
    let mut window_bits = opts.window_bits;
    if opts.raw && window_bits > 0 {
        window_bits = -window_bits;
    } else if opts.gzip && window_bits > 0 && window_bits < 16 {
        window_bits += 16;
    }

    let mut strm = ZStream::new();
    let mut s = DeflateState::new();
    let status = deflate_init2(
        &mut strm,
        &mut s,
        opts.level,
        Z_DEFLATED,
        window_bits,
        opts.mem_level,
        opts.strategy,
        opts.legacy_hash,
    );
    assert_eq!(status, Z_OK, "deflate_init2 rejected these options");

    strm.input = data.to_vec();
    strm.next_in = 0;
    strm.avail_in = data.len();
    strm.avail_out = 0;

    let mut out = Vec::new();
    loop {
        if strm.avail_out == 0 {
            strm.output = vec![0u8; opts.chunk_size];
            strm.next_out = 0;
            strm.avail_out = opts.chunk_size;
        }

        let ret = deflate(&mut strm, &mut s, Z_FINISH);

        if ret == Z_STREAM_END {
            out.extend_from_slice(&strm.output[..strm.next_out]);
            return out;
        }
        assert_eq!(ret, Z_OK, "deflate failed: {}", strm.msg);

        if strm.avail_out == 0 {
            out.extend_from_slice(&strm.output);
            continue;
        }
        if strm.next_out > 0 {
            out.extend_from_slice(&strm.output[..strm.next_out]);
            strm.avail_out = 0;
            continue;
        }
        panic!("deflate made no progress with output space remaining");
    }
}

fn sig(out: &[u8]) -> (usize, String) {
    (out.len(), format!("{:08X}", crc32(0, out, out.len(), 0)))
}

fn check(label: &str, data: &[u8], opts: Options, len: usize, crc: &str) {
    let got = deflate_all(data, &opts);
    assert_eq!(sig(&got), (len, crc.to_string()), "{label}");
}

fn lorem() -> Vec<u8> {
    fixture("fixtures/samples/lorem.txt")
}
fn lorem_en() -> Vec<u8> {
    fixture("fixtures/samples/lorem_en_100k.txt")
}
fn lorem_utf() -> Vec<u8> {
    fixture("fixtures/samples/lorem_utf_100k.txt")
}
fn jpeg() -> Vec<u8> {
    fixture("fixtures/samples/lorem_cat.jpeg")
}

#[test]
fn matches_the_oracle_at_every_compression_level() {
    let small = lorem();
    let big = lorem_en();

    // Levels 1-3 take deflate_fast, 4-9 deflate_slow, 0 deflate_stored, so
    // this one table exercises three of the five block compressors.
    let expected: [(i32, usize, &str, usize, &str); 10] = [
        (0, 18, "42348D70", 101366, "F884B11B"),
        (1, 15, "725951C8", 29886, "013E7D2E"),
        (2, 15, "03C62EA3", 29343, "D1ED21CF"),
        (3, 15, "03C62EA3", 29023, "11B91F3C"),
        (4, 15, "03C62EA3", 27511, "97EB60D0"),
        (5, 15, "03C62EA3", 26811, "87E33C04"),
        (6, 15, "2062F21D", 26680, "CF4B4EE6"),
        (7, 15, "99194E5A", 26682, "4BF13B77"),
        (8, 15, "99194E5A", 26681, "4DC4E1B3"),
        (9, 15, "99194E5A", 26681, "4DC4E1B3"),
    ];

    for (level, slen, scrc, blen, bcrc) in expected {
        check(
            &format!("lvl{level}:lorem"),
            &small,
            Options {
                level,
                ..Default::default()
            },
            slen,
            scrc,
        );
        check(
            &format!("lvl{level}:lorem_en"),
            &big,
            Options {
                level,
                ..Default::default()
            },
            blen,
            bcrc,
        );
    }
}

#[test]
fn matches_the_oracle_for_every_strategy() {
    let big = lorem_en();
    let runs = vec![0x41u8; 4096];

    // Strategy 2 is deflate_huff and 3 is deflate_rle, the two compressors the
    // level table never reaches. 4 is Z_FIXED, which forces static trees.
    let expected: [(i32, usize, &str, usize, &str); 5] = [
        (0, 26680, "CF4B4EE6", 28, "3AD32029"),
        (1, 26670, "2616B24E", 28, "3AD32029"),
        (2, 54299, "52BDE9A6", 531, "A42E53BD"),
        (3, 54298, "161051E5", 27, "13B2FD66"),
        (4, 32744, "4466770F", 36, "5D977558"),
    ];

    for (strategy, blen, bcrc, rlen, rcrc) in expected {
        check(
            &format!("strat{strategy}:lorem_en"),
            &big,
            Options {
                strategy,
                ..Default::default()
            },
            blen,
            bcrc,
        );
        check(
            &format!("strat{strategy}:runs"),
            &runs,
            Options {
                strategy,
                ..Default::default()
            },
            rlen,
            rcrc,
        );
    }
}

#[test]
fn matches_the_oracle_for_every_wrapper() {
    let big = lorem_en();

    check(
        "raw:lorem_en",
        &big,
        Options {
            raw: true,
            ..Default::default()
        },
        26674,
        "13F197B0",
    );
    check(
        "gzip:lorem_en",
        &big,
        Options {
            gzip: true,
            ..Default::default()
        },
        26692,
        "295A1ECD",
    );
    check("zlib:lorem_en", &big, Options::default(), 26680, "CF4B4EE6");
}

#[test]
fn matches_the_oracle_across_window_and_memory_sizes() {
    let big = lorem_en();

    for (wb, len, crc) in [
        (9, 48775, "2DB093BA"),
        (10, 40470, "928E01E6"),
        (12, 29020, "614418BD"),
        (15, 26680, "CF4B4EE6"),
    ] {
        check(
            &format!("wb{wb}:lorem_en"),
            &big,
            Options {
                window_bits: wb,
                ..Default::default()
            },
            len,
            crc,
        );
    }

    // memLevel moves lit_bufsize and hash_bits, so it changes both when blocks
    // are flushed and which matches the hash chains find.
    for (ml, len, crc) in [
        (1, 28869, "9FA4C2DE"),
        (4, 26624, "316F84A0"),
        (8, 26680, "CF4B4EE6"),
        (9, 26680, "CF4B4EE6"),
    ] {
        check(
            &format!("ml{ml}:lorem_en"),
            &big,
            Options {
                mem_level: ml,
                ..Default::default()
            },
            len,
            crc,
        );
    }
}

#[test]
fn matches_the_oracle_with_the_classic_zlib_hash() {
    // legacyHash swaps the 4-byte ANZAC++ hash for zlib's shift-and-xor one,
    // which finds different matches and so produces different bytes. A port
    // that implemented only one of the two still passes every test above.
    check(
        "legacy:lorem_en",
        &lorem_en(),
        Options {
            legacy_hash: true,
            ..Default::default()
        },
        26739,
        "FF38C8BD",
    );
    check(
        "legacy:lorem_utf",
        &lorem_utf(),
        Options {
            legacy_hash: true,
            ..Default::default()
        },
        1871,
        "1574EB8E",
    );
    check(
        "legacy:jpeg",
        &jpeg(),
        Options {
            legacy_hash: true,
            ..Default::default()
        },
        74270,
        "A5ACA38B",
    );
}

#[test]
fn matches_the_oracle_on_text_binary_and_degenerate_input() {
    check(
        "dflt:hello",
        b"hello hello hello world",
        Options::default(),
        21,
        "1D93715C",
    );
    check("dflt:empty", &[], Options::default(), 8, "C36C0B3C");
    check(
        "dflt:runs",
        &vec![0x41u8; 4096],
        Options::default(),
        28,
        "3AD32029",
    );
    check(
        "dflt:lorem_utf",
        &lorem_utf(),
        Options::default(),
        1860,
        "E2BEA0E6",
    );
    check("dflt:jpeg", &jpeg(), Options::default(), 74381, "FD6AE13D");
    check(
        "dflt:gif",
        &fixture("fixtures/samples/blank.gif"),
        Options::default(),
        55,
        "30DAC839",
    );
}

#[test]
fn chunk_size_changes_the_call_pattern_but_not_the_bytes() {
    check(
        "chunk1k:lorem_en",
        &lorem_en(),
        Options {
            chunk_size: 1024,
            ..Default::default()
        },
        26680,
        "CF4B4EE6",
    );
}
