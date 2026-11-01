//! Small helpers shared by the deflate and inflate wrappers.

/// Join a list of chunks into one buffer.
///
/// The original sums the lengths first and then copies into a single
/// pre-sized `Uint8Array`, rather than concatenating pairwise. That matters
/// for the streaming API, where `onEnd` glues up to thousands of 16 KiB
/// chunks: the one-allocation form is linear, the pairwise form is quadratic.
/// `with_capacity` plus `extend_from_slice` keeps that property.
pub fn flatten_chunks(chunks: &[Vec<u8>]) -> Vec<u8> {
    let total = chunks.iter().map(|c| c.len()).sum();
    let mut result = Vec::with_capacity(total);

    for chunk in chunks {
        result.extend_from_slice(chunk);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::flatten_chunks;

    #[test]
    fn joins_in_order() {
        let chunks = vec![vec![1u8, 2, 3], vec![4, 5], vec![], vec![6]];
        assert_eq!(flatten_chunks(&chunks), vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn empty_input_yields_empty_output() {
        assert!(flatten_chunks(&[]).is_empty());
        assert!(flatten_chunks(&[vec![], vec![]]).is_empty());
    }

    #[test]
    fn allocates_exactly_once() {
        let chunks = vec![vec![0u8; 100], vec![0u8; 200]];
        let out = flatten_chunks(&chunks);
        assert_eq!(out.len(), 300);
        assert_eq!(out.capacity(), 300, "must be pre-sized, not grown pairwise");
    }
}
