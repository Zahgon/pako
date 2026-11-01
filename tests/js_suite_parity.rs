//! The cases the repository's own JavaScript suites cover that the other
//! Rust suites do not reach.
//!
//! Every expected value was produced by running the original wrappers over the
//! same input. These are the awkward corners: a gzip timestamp past the signed
//! 32-bit boundary, an output length that lands exactly on a chunk boundary,
//! the `memLevel: 1` regression sample, `Z_FIXED` on incompressible data, and
//! the contracts around a stream that failed rather than ended.

use std::path::Path;

use pako::zlib::crc32::crc32;
use pako::zlib::gzheader::GzHeader;
use pako::{
    deflate, deflate_raw, inflate, ungzip, Deflate, DeflateOptions, Inflate, InflateOptions,
    Z_DATA_ERROR, Z_FINISH, Z_FIXED, Z_NO_FLUSH, Z_OK, Z_STREAM_ERROR, Z_SYNC_FLUSH,
};

fn fixture(rel: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("test").join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn sig(out: &[u8]) -> (usize, String) {
    (out.len(), format!("{:08X}", crc32(0, out, out.len(), 0)))
}

#[test]
fn a_gzip_timestamp_past_2038_round_trips_unsigned() {
    // 4_000_000_000 exceeds 2^31. A port holding mtime as a signed 32-bit int
    // reads it back negative, which is the 2038 problem in miniature.
    let mut d = Deflate::new(DeflateOptions::new().gzip(true)).expect("Deflate::new");
    let mut h = GzHeader::new();
    h.time = 4_000_000_000;
    h.os = 3;
    assert_eq!(d.set_header(h), Z_OK);
    d.push(b"x", Z_FINISH);
    assert_eq!(sig(&d.result), (21, String::from("FF2A8E6F")));

    let mut inf = Inflate::new(InflateOptions::new()).expect("Inflate::new");
    inf.capture_header();
    assert!(inf.push(&d.result, Z_FINISH), "{}", inf.msg);
    assert_eq!(inf.header.expect("header").time, 4_000_000_000);
}

#[test]
fn output_landing_exactly_on_a_chunk_boundary_is_not_truncated_or_doubled() {
    // This 53-byte input compresses to exactly 64 bytes, so with chunkSize 64
    // the buffer fills on the very call that ends the stream. A port that
    // emitted the tail both on "buffer full" and on "stream end" doubles it
    // here; one that emitted on neither loses it.
    let data: Vec<u8> = (0..53u32).map(|i| (i * 7) as u8).collect();
    assert_eq!(sig(&data), (53, String::from("814FD5B2")));

    let mut d = Deflate::new(DeflateOptions::new().chunk_size(64)).expect("Deflate::new");
    d.push(&data, Z_FINISH);
    assert_eq!(sig(&d.result), (64, String::from("9A7B8C46")));

    let mut inf = Inflate::new(InflateOptions::new().chunk_size(53)).expect("Inflate::new");
    assert!(inf.push(&d.result, Z_FINISH), "{}", inf.msg);
    assert_eq!(inf.err, Z_OK);
    assert_eq!(sig(&inf.result), (53, String::from("814FD5B2")));
}

#[test]
fn the_issue_78_sample_round_trips_at_the_smallest_memory_level() {
    // memLevel 1 gives the smallest lit_bufsize, so blocks flush far more
    // often and the symbol buffer wraps where it otherwise never would.
    let sample = fixture("fixtures/issue_78.bin");
    assert_eq!(sig(&sample), (1109, String::from("A73F1BFE")));

    let z = deflate(&sample, DeflateOptions::new().mem_level(1)).expect("deflate");
    assert_eq!(sig(&z), (940, String::from("838CC8D6")));

    let back = inflate(&z, InflateOptions::new()).expect("inflate");
    assert_eq!(back, sample);
}

#[test]
fn z_fixed_on_incompressible_data_selects_the_same_block_type() {
    // Z_FIXED forces static trees, so the stored/static/dynamic choice in
    // tr_flush_block is exercised on data that does not compress.
    let rnd: Vec<u8> = (0..1024u32)
        .map(|i| i.wrapping_mul(2_654_435_761) as u8)
        .collect();
    assert_eq!(sig(&rnd), (1024, String::from("B6E77BD0")));

    let z = deflate(&rnd, DeflateOptions::new().strategy(Z_FIXED)).expect("deflate");
    assert_eq!(sig(&z), (286, String::from("77C914EB")));

    let back = inflate(&z, InflateOptions::new()).expect("inflate");
    assert_eq!(back, rnd);
}

#[test]
fn an_out_of_range_flush_mode_fails_instead_of_hanging() {
    // 7 is past Z_TREES. The original returns Z_STREAM_ERROR rather than
    // looping forever waiting for progress that cannot happen.
    let mut d = Deflate::new(DeflateOptions::new()).expect("Deflate::new");
    let ok = d.push(b"hello", 7);
    assert!(!ok);
    assert_eq!(d.err, Z_STREAM_ERROR);
    assert_eq!(d.msg, "stream error");
}

#[test]
fn raw_mode_with_window_bits_zero_forces_the_maximum_window() {
    // There is no header to auto-detect from in raw mode, so windowBits 0 has
    // to become -15 rather than being passed through as zero.
    let z = deflate_raw(b"hello", DeflateOptions::new()).expect("deflate_raw");

    let mut inf =
        Inflate::new(InflateOptions::new().raw(true).window_bits(0)).expect("Inflate::new");
    assert!(inf.push(&z, Z_FINISH), "{}", inf.msg);
    assert_eq!(inf.err, Z_OK);
    assert_eq!(sig(&inf.result), (5, String::from("3610A686")));
}

#[test]
fn pushes_after_a_failed_stream_keep_reporting_the_failure() {
    // The mirror of the ended-successfully case: a failed stream must keep
    // returning false and keep its original error, not reset to Z_OK.
    let mut inf = Inflate::new(InflateOptions::new()).expect("Inflate::new");
    let bad = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    assert!(!inf.push(&bad, Z_FINISH));
    assert!(
        !inf.push(&bad, Z_FINISH),
        "a second push must also report false"
    );
    assert_eq!(inf.err, Z_DATA_ERROR);
    assert_eq!(inf.msg, "incorrect header check");
}

#[test]
fn a_dictionary_applies_across_multiple_pushes() {
    // The dictionary seeds the window before any input, so splitting the input
    // must not change the bytes: this is the same 22-byte output the one-shot
    // dictionary test produces.
    let dict = b"abcdefghij";

    let mut d =
        Deflate::new(DeflateOptions::new().dictionary(dict.to_vec())).expect("Deflate::new");
    d.push(b"abcdefghij ", Z_NO_FLUSH);
    d.push(b"abcdefghij hello", Z_FINISH);
    assert_eq!(sig(&d.result), (22, String::from("11A8A895")));

    let mut inf =
        Inflate::new(InflateOptions::new().dictionary(dict.to_vec())).expect("Inflate::new");
    assert!(inf.push(&d.result, Z_FINISH), "{}", inf.msg);
    assert_eq!(sig(&inf.result), (27, String::from("4983E139")));
}

#[test]
fn inflate_with_sync_flush_emits_the_tail_without_emitting_it_twice() {
    let src = b"one two three four five";
    let z = deflate(src, DeflateOptions::new()).expect("deflate");

    let mut inf = Inflate::new(InflateOptions::new()).expect("Inflate::new");

    inf.push(&z[..10], Z_SYNC_FLUSH);
    let after_first: usize = inf.chunks.iter().map(|c| c.len()).sum();
    assert_eq!(after_first, 7, "the first frame must come out immediately");

    inf.push(&z[10..], Z_SYNC_FLUSH);
    // The stream ended, so on_end moved the chunks into result rather than
    // leaving them to be emitted a second time.
    let after_second: usize = inf.chunks.iter().map(|c| c.len()).sum();
    assert_eq!(after_second, 0);
    assert!(inf.ended);
    assert_eq!(inf.result, src);
}

#[test]
fn utf8_text_survives_a_round_trip_through_the_wrappers() {
    // Multi-byte sequences, including one above the BMP, so a port that
    // decoded output byte by byte as Latin-1 fails here.
    let text = "Привет мир — ёжик 🦔 test";
    // The oracle reports length 25 because JavaScript counts UTF-16 code
    // units and the hedgehog is a surrogate pair; the same text is 24 chars.
    assert_eq!(text.encode_utf16().count(), 25);
    assert_eq!(text.chars().count(), 24);

    let z = deflate(text.as_bytes(), DeflateOptions::new()).expect("deflate");
    let back = inflate(&z, InflateOptions::new()).expect("inflate");
    assert_eq!(String::from_utf8(back).expect("valid utf8"), text);
}

#[test]
fn multistream_gzip_decodes_every_member_through_the_wrapper() {
    for (file, len, crc) in [
        ("fixtures/gzip-joined.gz", 48usize, "D25A4D85"),
        ("fixtures/gzip-joined-bgzip.gz", 65569, "E38722B5"),
    ] {
        let out = ungzip(&fixture(file), InflateOptions::new()).expect(file);
        assert_eq!(sig(&out), (len, crc.to_string()), "{file}");
    }
}
