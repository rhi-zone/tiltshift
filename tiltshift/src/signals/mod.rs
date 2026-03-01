pub mod entropy;
pub mod magic;
pub mod strings;

use crate::types::Signal;

/// Run all signal extractors over `data` and return every signal found,
/// in offset order.
pub fn extract_all(data: &[u8], entropy_block_size: usize) -> Vec<Signal> {
    let stride = entropy_block_size / 4;
    let mut signals = Vec::new();
    signals.extend(magic::scan(data));
    signals.extend(strings::scan_null_terminated(data));
    signals.extend(entropy::entropy_map(
        data,
        entropy_block_size,
        stride.max(1),
    ));
    signals.sort_by_key(|s| s.region.offset);
    signals
}
