//! The zlib core: the two checksums, the stream descriptor, the gzip header,
//! and (as they land) the deflate and inflate engines.
//!
//! Module boundaries follow the original `src/zlib/` directory one for one, so
//! a reader can diff a Rust file against its `.mjs` counterpart.

pub mod adler32;
pub mod constants;
pub mod crc32;
pub mod deflate;
pub mod deflate_state;
pub mod gzheader;
pub mod inffast;
pub mod inflate;
pub mod inflate_state;
pub mod inftrees;
pub mod messages;
pub mod zstream;

pub use adler32::adler32;
pub use crc32::crc32;
pub use deflate::{
    deflate, deflate_end, deflate_init, deflate_init2, deflate_reset, deflate_reset_keep,
    deflate_set_dictionary, deflate_set_header,
};
pub use deflate_state::{DeflateState, TreeKind};
pub use gzheader::GzHeader;
pub use inffast::inflate_fast;
pub use inflate::{
    inflate, inflate_end, inflate_get_header, inflate_init, inflate_init2, inflate_reset,
    inflate_reset2, inflate_reset_keep, inflate_set_dictionary,
};
pub use inflate_state::{InflateState, Tables};
pub use inftrees::{inflate_table, CodeType};
pub use messages::message;
pub use zstream::ZStream;
pub mod trees;
