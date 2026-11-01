pako
==========================================

[![CI](https://github.com/nodeca/pako/workflows/CI/badge.svg)](https://github.com/nodeca/pako/actions)

> Very fast zlib-compatible compression for Rust.

## Why pako is cool

- __Binary-equivalent output.__ Pako produces the same deflate/gzip bytes as
  original [zlib](http://www.zlib.net/) (1.3.2) and Node.js' patched zlib.
- __No dependencies.__ Deflate, inflate, the Huffman tree builder and both
  checksums are implemented here rather than bound to a C library.


## Install

```toml
[dependencies]
pako = "3.0"
```


Examples / API
--------------

```rust
use pako::{deflate, inflate, DeflateOptions, InflateOptions};

// Deflate
let input: &[u8] = b"...";
let output = deflate(input, DeflateOptions::new())?;

// Inflate (the simple wrapper returns Err on a broken stream)
let restored = inflate(&output, InflateOptions::new())?;
```

```rust
use pako::{Deflate, DeflateOptions, Inflate, InflateOptions, Z_FINISH, Z_NO_FLUSH};

//
// Alternate interface for chunking, reporting errors in a field
//

let mut deflator = Deflate::new(DeflateOptions::new())?;

deflator.push(chunk1, Z_NO_FLUSH);
deflator.push(chunk2, Z_NO_FLUSH);
// ...
deflator.push(chunk_last, Z_FINISH); // Z_FINISH says this chunk is last

if deflator.err != 0 {
    println!("{}", deflator.msg);
}

let output = deflator.result;


let mut inflator = Inflate::new(InflateOptions::new())?;

inflator.push(chunk1, Z_NO_FLUSH);
inflator.push(chunk2, Z_NO_FLUSH);
// ...
inflator.push(chunk_last, Z_FINISH);

if inflator.err != 0 {
    println!("{}", inflator.msg);
}

let output = inflator.result;
```

Options are built by chaining, so only the ones you care about are named:

```rust
use pako::{deflate, deflate_raw, gzip, DeflateOptions, Z_RLE};

let a = deflate(input, DeflateOptions::new().level(9))?;
let b = gzip(input, DeflateOptions::new().strategy(Z_RLE))?;
let c = deflate_raw(input, DeflateOptions::new().dictionary(dict))?;
```

By default pako uses the ANZAC++ hash, which matches recent (chromium) Node.js
output. Set `legacy_hash(true)` for the classic zlib hash, which matches
canonical zlib byte for byte.

```rust
use pako::{deflate, DeflateOptions};

let canonical = deflate(input, DeflateOptions::new().legacy_hash(true))?;
```

To work with text, compress its UTF-8 bytes and decode the result back:

```rust
use pako::{deflate, inflate, DeflateOptions, InflateOptions};

let text = "pako is super awesome";
let compressed = deflate(text.as_bytes(), DeflateOptions::new())?;
let restored = String::from_utf8(inflate(&compressed, InflateOptions::new())?)?;
```


## Notes

Pako does not contain some specific zlib functions:

- __deflate__ -  methods `deflateCopy`, `deflateBound`, `deflateParams`,
  `deflatePending`, `deflatePrime`, `deflateTune`.
- __inflate__ - methods `inflateCopy`, `inflateMark`,
  `inflatePrime`, `inflateGetDictionary`, `inflateSync`, `inflateSyncPoint`, `inflateUndermine`.
- High level inflate/deflate wrappers may not support some flush modes.


## Authors

- Andrey Tupitsin [@anrd83](https://github.com/andr83)
- Vitaly Puzrin [@puzrin](https://github.com/puzrin)

Personal thanks to:

- Vyacheslav Egorov ([@mraleph](https://github.com/mraleph)) for his awesome
  tutorials about optimising JS code for v8, [IRHydra](http://mrale.ph/irhydra/)
  tool and his advices.
- David Duponchel ([@dduponchel](https://github.com/dduponchel)) for help with
  testing.

Original implementation (in C):

- [zlib](http://zlib.net/) by Jean-loup Gailly and Mark Adler.


## License

- MIT - all files, except `/src/zlib` folder
- ZLIB - `/src/zlib` content
