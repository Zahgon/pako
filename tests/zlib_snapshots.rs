//! Byte-for-byte equality with canonical zlib, via the repository's own
//! snapshot fixtures.
//!
//! This is the strongest evidence in the suite and the only part that does not
//! trust the JavaScript implementation: `test/zlib/zlib_snapshots/*.bin` holds
//! the output of real zlib over `lorem_en_100k.txt`, recorded independently of
//! pako. `legacy_hash` selects the classic zlib hash, which is what makes the
//! comparison meaningful; the default ANZAC++ hash matches node.js instead and
//! is covered by the pako-derived suites.
//!
//! Mirrors `test/zlib/binary_compare.test.mjs`.

use std::path::{Path, PathBuf};

use pako::{deflate, deflate_raw, gzip, DeflateOptions};

fn repo(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read(rel: &str) -> Vec<u8> {
    let p = repo(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

fn sample() -> Vec<u8> {
    read("test/fixtures/samples/lorem_en_100k.txt")
}

fn snapshot(name: &str) -> Vec<u8> {
    read(&format!("test/zlib/zlib_snapshots/{name}"))
}

/// Base options for every comparison: the classic zlib hash.
fn legacy() -> DeflateOptions {
    DeflateOptions::new().legacy_hash(true)
}

fn assert_matches(got: &[u8], name: &str) {
    let want = snapshot(name);
    assert_eq!(got.len(), want.len(), "{name}: length");
    if got != want.as_slice() {
        let at = got
            .iter()
            .zip(want.iter())
            .position(|(a, b)| a != b)
            .expect("lengths agreed but contents differ");
        panic!(
            "{name}: first difference at byte {at}: got {:#04x}, zlib has {:#04x}",
            got[at], want[at]
        );
    }
}

#[test]
fn matches_canonical_zlib_with_default_options() {
    assert_matches(
        &deflate(&sample(), legacy()).expect("deflate"),
        "deflate.bin",
    );
    assert_matches(
        &deflate_raw(&sample(), legacy()).expect("deflate_raw"),
        "deflateRaw.bin",
    );
}

#[test]
fn matches_canonical_zlib_for_gzip_apart_from_the_os_byte() {
    // Byte 9 of a gzip header is the OS code, which varies with the platform
    // that recorded the fixture, so the original's test overrides it. No extra
    // header fields are present, so its position is fixed.
    let got = gzip(&sample(), legacy()).expect("gzip");
    let mut want = snapshot("gzip.bin");
    assert_eq!(got.len(), want.len(), "gzip.bin: length");
    want[9] = got[9];
    assert_eq!(got, want, "gzip.bin");
}

#[test]
fn matches_canonical_zlib_at_every_level() {
    for level in [9, 8, 7, 6, 5, 4, 3, 2, 1, -1] {
        let got = deflate(&sample(), legacy().level(level)).expect("deflate");
        assert_matches(&got, &format!("deflate_level={level}.bin"));
    }
}

#[test]
fn matches_canonical_zlib_at_every_window_size() {
    for wb in [15, 14, 13, 12, 11, 10, 9, 8] {
        let got = deflate(&sample(), legacy().window_bits(wb)).expect("deflate");
        assert_matches(&got, &format!("deflate_windowBits={wb}.bin"));
    }

    // A negative windowBits requests raw deflate without setting `raw`.
    let got = deflate(&sample(), legacy().window_bits(-15)).expect("deflate");
    assert_matches(&got, "deflateRaw_windowBits=15.bin");
}

#[test]
fn matches_canonical_zlib_at_every_memory_level() {
    for ml in [9, 8, 7, 6, 5, 4, 3, 2, 1] {
        let got = deflate(&sample(), legacy().mem_level(ml)).expect("deflate");
        assert_matches(&got, &format!("deflate_memLevel={ml}.bin"));
    }
}

#[test]
fn matches_canonical_zlib_for_every_strategy() {
    for strategy in [0, 1, 2, 3, 4] {
        let got = deflate(&sample(), legacy().strategy(strategy)).expect("deflate");
        assert_matches(&got, &format!("deflate_strategy={strategy}.bin"));
    }
}

#[test]
fn matches_canonical_zlib_for_raw_output() {
    // The wrapper is the only difference, so one fast level and one slow level
    // cover it.
    for level in [4, 1] {
        let got = deflate_raw(&sample(), legacy().level(level)).expect("deflate_raw");
        assert_matches(&got, &format!("deflateRaw_level={level}.bin"));
    }
}

#[test]
fn matches_canonical_zlib_with_a_preset_dictionary() {
    // Note the alphabet skips `q`, exactly as the original's fixture does.
    let trivial = b"abcdefghijklmnoprstuvwxyz";
    let got = deflate(&sample(), legacy().dictionary(trivial.to_vec())).expect("deflate");
    assert_matches(&got, "deflate_dictionary=trivial.bin");

    // The SPDY dictionary is 910 bytes, so it exercises a dictionary longer
    // than the window prefill path handles in one go.
    let spdy = read("test/fixtures/spdy_dict.txt");
    let got = deflate(&sample(), legacy().dictionary(spdy)).expect("deflate");
    assert_matches(&got, "deflate_dictionary=spdy.bin");
}
