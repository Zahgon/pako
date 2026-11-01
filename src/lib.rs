//! pako: zlib (deflate/inflate) in pure Rust.
//!
//! A port of the pako JavaScript library, which is itself a hand
//! transliteration of Jean-loup Gailly and Mark Adler's zlib. Output is
//! bit-exact with zlib at every level, strategy and window size, which is the
//! property the test suite checks against recorded fixtures.
//!
//! No dependencies: deflate, inflate, the Huffman tree builder and both
//! checksums are implemented here rather than delegated to a C library.

pub mod deflate_api;
pub mod inflate_api;
pub mod utils;
pub mod zlib;

pub use deflate_api::{deflate, deflate_raw, gzip, Deflate, DeflateOptions};
pub use inflate_api::{inflate, inflate_raw, ungzip, Inflate, InflateOptions};
pub use utils::flatten_chunks;

pub use zlib::constants::{
    Z_BEST_COMPRESSION, Z_BEST_SPEED, Z_BINARY, Z_BLOCK, Z_BUF_ERROR, Z_DATA_ERROR,
    Z_DEFAULT_COMPRESSION, Z_DEFAULT_STRATEGY, Z_DEFLATED, Z_ERRNO, Z_FILTERED, Z_FINISH, Z_FIXED,
    Z_FULL_FLUSH, Z_HUFFMAN_ONLY, Z_MEM_ERROR, Z_NEED_DICT, Z_NO_COMPRESSION, Z_NO_FLUSH, Z_OK,
    Z_PARTIAL_FLUSH, Z_RLE, Z_STREAM_END, Z_STREAM_ERROR, Z_SYNC_FLUSH, Z_TEXT, Z_TREES, Z_UNKNOWN,
};
pub use zlib::{adler32, crc32, message, GzHeader, ZStream};
