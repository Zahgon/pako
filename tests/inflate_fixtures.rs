//! End-to-end decode of the repository's own compressed fixtures.
//!
//! Every expected length and CRC-32 below was produced by running the
//! JavaScript original over the same fixture file, so this is a differential
//! test against the implementation being replaced rather than against values
//! chosen here. It is the first test that exercises `inftrees`, `inffast` and
//! the `inflate` mode machine together: the unit tests upstream of it can only
//! check tables and checksums in isolation.

use std::path::{Path, PathBuf};

use pako::zlib::crc32::crc32;
use pako::zlib::inflate::{inflate, inflate_init2, inflate_reset};
use pako::zlib::inflate_state::InflateState;
use pako::zlib::zstream::ZStream;
use pako::{Z_BUF_ERROR, Z_NO_FLUSH, Z_OK, Z_STREAM_END};

/// Window-bits values pako's wrappers pass for each stream flavour.
const ZLIB: i32 = 15;
/// 15 + 32 requests zlib/gzip auto-detection, as `ungzip` relies on.
const AUTO: i32 = 47;
const RAW: i32 = -15;

/// pako's default `chunkSize`, so the output is produced in the same number of
/// pieces and the window is refreshed at the same points.
const CHUNK: usize = 16384;

fn fixture(rel: &str) -> Vec<u8> {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("test").join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// Drive the low-level decoder the way `Inflate.push` does: hand it the whole
/// input, then a fresh output chunk whenever the previous one fills.
fn inflate_all(data: &[u8], window_bits: i32) -> Result<Vec<u8>, (i32, String)> {
    let mut strm = ZStream::new();
    let mut state = InflateState::new();

    let status = inflate_init2(&mut strm, &mut state, window_bits);
    assert_eq!(
        status, Z_OK,
        "inflate_init2 rejected windowBits {window_bits}"
    );

    strm.input = data.to_vec();
    strm.next_in = 0;
    strm.avail_in = data.len();

    let mut out = Vec::new();
    loop {
        strm.output = vec![0u8; CHUNK];
        strm.next_out = 0;
        strm.avail_out = CHUNK;

        let mut ret = inflate(&mut strm, &mut state, Z_NO_FLUSH);
        out.extend_from_slice(&strm.output[..strm.next_out]);

        // Only gzip defines concatenated members (RFC 1952: a gzip file is "a
        // series of members"). A zlib stream ends after its ADLER32 and a raw
        // stream after its final block, so trailing bytes there are not ours
        // to read. `flags != 0` is what distinguishes a decoded gzip header
        // from an auto-detected zlib one, and a trailing zero byte is padding
        // rather than a member, since no member can begin with 0.
        while strm.avail_in > 0
            && ret == Z_STREAM_END
            && state.wrap & 2 != 0
            && state.flags != 0
            && strm.input[strm.next_in] != 0
        {
            inflate_reset(&mut strm, &mut state);
            strm.next_out = 0;
            strm.avail_out = CHUNK;
            ret = inflate(&mut strm, &mut state, Z_NO_FLUSH);
            out.extend_from_slice(&strm.output[..strm.next_out]);
        }

        match ret {
            Z_STREAM_END => return Ok(out),
            Z_OK => {
                // Neither buffer moved: no progress is possible, so stop
                // rather than spin. `Inflate.push` reaches the same decision
                // by way of avail_in hitting zero.
                if strm.avail_in == 0 && strm.next_out == 0 {
                    return Ok(out);
                }
            }
            Z_BUF_ERROR if strm.avail_in == 0 => return Ok(out),
            err => return Err((err, strm.msg.clone())),
        }
    }
}

fn sig(out: &[u8]) -> (usize, String) {
    (out.len(), format!("{:08X}", crc32(0, out, out.len(), 0)))
}

fn assert_matches_oracle(rel: &str, window_bits: i32, len: usize, crc: &str) {
    let data = fixture(rel);
    let out = match inflate_all(&data, window_bits) {
        Ok(out) => out,
        Err((code, msg)) => panic!("{rel}: inflate failed with {code}: {msg}"),
    };
    assert_eq!(sig(&out), (len, crc.to_string()), "{rel}");
}

#[test]
fn decodes_a_zlib_stream_whose_header_understates_the_window() {
    // The header advertises a smaller window than the data needs. pako
    // deliberately forces `options.windowBits` here instead of trusting the
    // header, so a port that followed zlib's `dmax = 1 << len` reads a
    // distance as too far back and fails on exactly this fixture.
    assert_matches_oracle("fixtures/bad_wbits.deflate", ZLIB, 71731, "9AD182D8");
}

#[test]
fn decodes_gzip_members() {
    assert_matches_oracle("fixtures/gzip-joined.gz", AUTO, 48, "D25A4D85");
    assert_matches_oracle("fixtures/gzip-joined-bgzip.gz", AUTO, 65569, "E38722B5");
}

#[test]
fn decodes_raw_deflate_streams() {
    // Real-world raw streams, large enough to drive the inffast loop and to
    // refresh the sliding window several times over.
    assert_matches_oracle(
        "fixtures/samples_deflated_raw/KW_Rocketry_1.compressed",
        RAW,
        1048596,
        "7EAEDB32",
    );
    assert_matches_oracle(
        "fixtures/samples_deflated_raw/shapefile.compressed",
        RAW,
        32769,
        "9078C4AC",
    );
    assert_matches_oracle(
        "fixtures/samples_deflated_raw/sheet2.compressed",
        RAW,
        272779,
        "6715F9E6",
    );
    assert_matches_oracle(
        "fixtures/samples_deflated_raw/sheet3.compressed",
        RAW,
        71051,
        "DAC9C198",
    );
    assert_matches_oracle(
        "fixtures/samples_deflated_raw/sheet4.compressed",
        RAW,
        38279,
        "8C211855",
    );
}

#[test]
fn rejects_a_corrupt_stream_rather_than_producing_garbage() {
    let mut data = fixture("fixtures/samples_deflated_raw/shapefile.compressed");
    // Flip bits in the middle of the compressed body, past the point where
    // the Huffman tables are read, so decoding starts and then goes wrong.
    let mid = data.len() / 2;
    data[mid] ^= 0xFF;
    data[mid + 1] ^= 0xFF;

    match inflate_all(&data, RAW) {
        Err((code, msg)) => {
            assert!(code < 0, "expected a negative status, got {code}");
            assert!(!msg.is_empty(), "a failure must carry zlib's message");
        }
        Ok(out) => {
            // A corrupt stream may still decode to *something*; what it must
            // not do is silently reproduce the original bytes.
            let (_, crc) = sig(&out);
            assert_ne!(crc, "9078C4AC", "corrupt input decoded to the clean output");
        }
    }
}
