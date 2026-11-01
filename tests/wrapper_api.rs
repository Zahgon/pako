//! The public `Deflate` / `Inflate` surface, against the JavaScript wrappers.
//!
//! Every expected value was produced by running the original `src/deflate.ts`
//! and `src/inflate.ts` over the same input. These are the entry points a
//! caller actually uses, and they carry behaviour the low-level engines cannot:
//! chunk-boundary independence, dictionary plumbing, gzip header round-trips,
//! and the difference between a stream that ended and one that was truncated.

use std::path::Path;

use pako::zlib::crc32::crc32;
use pako::zlib::gzheader::GzHeader;
use pako::{
    deflate, deflate_raw, gzip, inflate, inflate_raw, ungzip, Deflate, DeflateOptions, Inflate,
    InflateOptions, Z_BUF_ERROR, Z_FINISH, Z_NO_FLUSH, Z_OK, Z_SYNC_FLUSH,
};

fn fixture(rel: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("test").join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn lorem_en() -> Vec<u8> {
    fixture("fixtures/samples/lorem_en_100k.txt")
}

fn sig(out: &[u8]) -> (usize, String) {
    (out.len(), format!("{:08X}", crc32(0, out, out.len(), 0)))
}

#[test]
fn streaming_in_any_chunk_size_produces_the_one_shot_bytes() {
    // The chunk boundaries a caller happens to use must not reach the output.
    // A port that reset bit-buffer or hash state per push still passes the
    // one-shot bit-exactness suite and fails here.
    let data = lorem_en();

    for n in [1usize, 3, 17, 1024] {
        let mut d = Deflate::new(DeflateOptions::new()).expect("Deflate::new");
        let mut i = 0;
        while i < data.len() {
            let end = (i + n).min(data.len());
            let last = i + n >= data.len();
            d.push(&data[i..end], if last { Z_FINISH } else { Z_NO_FLUSH });
            i += n;
        }
        assert_eq!(
            sig(&d.result),
            (26680, String::from("CF4B4EE6")),
            "pushing {n} bytes at a time"
        );
    }
}

#[test]
fn sync_flush_emits_a_frame_without_ending_the_stream() {
    let mut d = Deflate::new(DeflateOptions::new()).expect("Deflate::new");

    d.push(b"frame one ", Z_SYNC_FLUSH);
    let after_first: usize = d.chunks.iter().map(|c| c.len()).sum();
    assert_eq!(
        after_first, 18,
        "Z_SYNC_FLUSH must push the first frame out immediately"
    );

    d.push(b"frame two", Z_FINISH);
    assert_eq!(sig(&d.result), (29, String::from("62AFB3D7")));
}

#[test]
fn a_dictionary_shortens_the_stream_and_round_trips() {
    let dict = b"abcdefghij";
    let data = b"abcdefghij abcdefghij hello";

    let dz = deflate(data, DeflateOptions::new().dictionary(dict.to_vec())).expect("deflate");
    assert_eq!(sig(&dz), (22, String::from("11A8A895")));

    let dr =
        deflate_raw(data, DeflateOptions::new().dictionary(dict.to_vec())).expect("deflate_raw");
    assert_eq!(sig(&dr), (12, String::from("A05FA115")));

    // Decoding needs the same dictionary; the zlib wrapper signals that with
    // Z_NEED_DICT, which the wrapper answers from its options.
    let iz = inflate(&dz, InflateOptions::new().dictionary(dict.to_vec())).expect("inflate");
    assert_eq!(sig(&iz), (27, String::from("4983E139")));
    assert_eq!(iz, data);

    let ir =
        inflate_raw(&dr, InflateOptions::new().dictionary(dict.to_vec())).expect("inflate_raw");
    assert_eq!(sig(&ir), (27, String::from("4983E139")));
    assert_eq!(ir, data);
}

#[test]
fn a_gzip_header_survives_the_round_trip_field_for_field() {
    let mut d = Deflate::new(DeflateOptions::new().gzip(true)).expect("Deflate::new");

    let mut h = GzHeader::new();
    h.hcrc = 1;
    h.time = 1234567890;
    h.os = 3;
    h.text = 1;
    h.name = Some(String::from("test name"));
    h.comment = Some(String::from("test comment"));
    h.extra = Some(vec![4, 5, 6]);
    assert_eq!(d.set_header(h), Z_OK);

    d.push(b"payload for the header test", Z_FINISH);
    assert_eq!(
        sig(&d.result),
        (77, String::from("58169D88")),
        "header bytes must match the original byte for byte"
    );

    let mut inf = Inflate::new(InflateOptions::new()).expect("Inflate::new");
    inf.capture_header();
    assert!(inf.push(&d.result, Z_FINISH), "inflate failed: {}", inf.msg);

    let read = inf
        .header
        .expect("header was requested before the first push");
    assert_eq!(read.name.as_deref(), Some("test name"));
    assert_eq!(read.comment.as_deref(), Some("test comment"));
    assert_eq!(read.extra.as_deref(), Some(&[4u8, 5, 6][..]));
    assert_eq!((read.hcrc, read.os, read.text), (1, 3, 1));
    assert_eq!(read.time, 1234567890);
    assert!(read.done);

    assert_eq!(sig(&inf.result), (27, String::from("1DDD8335")));
}

#[test]
fn trailing_bytes_after_a_zlib_stream_are_left_alone() {
    // A zlib stream ends after its ADLER32, so anything following it is not
    // ours to interpret. The decode must succeed and ignore the tail rather
    // than treat it as a second member, which only gzip allows.
    let z = deflate(b"hello", DeflateOptions::new()).expect("deflate");
    let mut with_tail = z.clone();
    with_tail.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    let mut inf = Inflate::new(InflateOptions::new()).expect("Inflate::new");
    assert!(inf.push(&with_tail, Z_FINISH), "msg: {}", inf.msg);
    assert_eq!(inf.err, Z_OK);
    assert_eq!(sig(&inf.result), (5, String::from("3610A686")));
    assert_eq!(inf.result, b"hello");
}

#[test]
fn a_truncated_stream_is_reported_rather_than_returned_as_partial() {
    // Returning the bytes decoded so far would be indistinguishable from a
    // complete decode, silently hiding the data loss.
    let z = deflate(&lorem_en(), DeflateOptions::new()).expect("deflate");

    let mut inf = Inflate::new(InflateOptions::new()).expect("Inflate::new");
    let ok = inf.push(&z[..z.len() - 20], Z_FINISH);

    assert!(!ok, "a truncated stream must not report success");
    assert_eq!(inf.err, Z_BUF_ERROR);
    assert_eq!(inf.msg, "buffer error");
}

#[test]
fn inflate_chunk_size_changes_the_call_pattern_but_not_the_output() {
    let source = lorem_en();
    let z = deflate(&source, DeflateOptions::new()).expect("deflate");

    let out = inflate(&z, InflateOptions::new().chunk_size(1024)).expect("inflate");
    assert_eq!(sig(&out), (101345, String::from("6E16C351")));
    assert_eq!(out, source);
}

#[test]
fn every_wrapper_pair_round_trips() {
    let source = lorem_en();
    assert_eq!(
        sig(&source),
        (101345, String::from("6E16C351")),
        "fixture changed"
    );

    let z = inflate(
        &deflate(&source, DeflateOptions::new()).expect("deflate"),
        InflateOptions::new(),
    )
    .expect("inflate");
    assert_eq!(z, source);

    let r = inflate_raw(
        &deflate_raw(&source, DeflateOptions::new()).expect("deflate_raw"),
        InflateOptions::new(),
    )
    .expect("inflate_raw");
    assert_eq!(r, source);

    let g = ungzip(
        &gzip(&source, DeflateOptions::new()).expect("gzip"),
        InflateOptions::new(),
    )
    .expect("ungzip");
    assert_eq!(g, source);
}

#[test]
fn pushes_after_the_stream_ended_are_no_ops() {
    // A compressed stream can end before the caller's data does, and the
    // caller cannot know that in advance, so the recorded outcome is reported
    // and the delivered result survives any trailing chunks.
    let z = deflate(b"hello", DeflateOptions::new()).expect("deflate");

    let mut inf = Inflate::new(InflateOptions::new()).expect("Inflate::new");
    assert!(inf.push(&z, Z_FINISH));
    let first = inf.result.clone();

    assert!(inf.ended);
    assert!(inf.push(b"\xde\xad\xbe\xef", Z_FINISH), "still Z_OK");
    assert_eq!(inf.result, first, "the delivered result must not change");
}

#[test]
fn bad_options_are_reported_rather_than_panicking() {
    // windowBits 3 is below zlib's minimum of 8; the original throws here.
    assert!(Inflate::new(InflateOptions::new().window_bits(3)).is_err());
    assert!(Deflate::new(DeflateOptions::new().level(10)).is_err());
    assert!(Deflate::new(DeflateOptions::new().mem_level(0)).is_err());

    // A dictionary cannot be combined with a gzip wrapper.
    assert!(
        Deflate::new(DeflateOptions::new().gzip(true).dictionary(b"abc".to_vec())).is_err(),
        "gzip + dictionary must be rejected"
    );
}
