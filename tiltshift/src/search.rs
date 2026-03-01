/// Find all non-overlapping occurrences of `pattern` in `data`.
///
/// Returns a sorted list of byte offsets at which `pattern` begins.
/// An empty pattern matches every position (returns `0..data.len()`).
pub fn find_all(data: &[u8], pattern: &[u8]) -> Vec<usize> {
    if pattern.is_empty() {
        return (0..data.len()).collect();
    }
    if pattern.len() > data.len() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    let mut i = 0;
    while i + pattern.len() <= data.len() {
        if data[i..i + pattern.len()] == *pattern {
            hits.push(i);
            i += pattern.len(); // non-overlapping
        } else {
            i += 1;
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_single_hit() {
        let data = b"hello world";
        assert_eq!(find_all(data, b"world"), vec![6]);
    }

    #[test]
    fn finds_multiple_hits() {
        let data = b"abababab";
        // non-overlapping: hits at 0, 2, 4, 6
        assert_eq!(find_all(data, b"ab"), vec![0, 2, 4, 6]);
    }

    #[test]
    fn no_match_returns_empty() {
        assert_eq!(find_all(b"hello", b"xyz"), vec![]);
    }

    #[test]
    fn pattern_longer_than_data() {
        assert_eq!(find_all(b"hi", b"hello world"), vec![]);
    }

    #[test]
    fn non_overlapping_skips_interior() {
        // overlapping would give 0,1,2 — non-overlapping gives 0,2
        let data = b"aaaa";
        assert_eq!(find_all(data, b"aa"), vec![0, 2]);
    }

    #[test]
    fn empty_data() {
        assert_eq!(find_all(b"", b"ab"), vec![]);
    }

    #[test]
    fn pattern_equal_to_data() {
        assert_eq!(find_all(b"abc", b"abc"), vec![0]);
    }
}
