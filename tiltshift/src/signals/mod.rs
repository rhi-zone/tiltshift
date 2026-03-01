pub mod alignment;
pub mod chisq;
pub mod chunk;
pub mod compress;
pub mod entropy;
pub mod length_prefix;
pub mod magic;
pub mod ngram;
pub mod numeric;
pub mod padding;
pub mod strings;
pub mod tlv;

use crate::corpus::Corpus;
use crate::types::Signal;

/// Run all signal extractors over `data` and return every signal found,
/// in offset order.
pub fn extract_all(data: &[u8], entropy_block_size: usize, corpus: &Corpus) -> Vec<Signal> {
    let stride = entropy_block_size / 4;
    let mut signals = Vec::new();
    signals.extend(magic::scan(data, corpus));
    signals.extend(strings::scan_null_terminated(data));
    signals.extend(length_prefix::scan_length_prefixed(data));
    signals.extend(chunk::scan_chunks(data));
    signals.extend(numeric::scan_numeric_landmarks(data));
    signals.extend(ngram::scan_ngrams(data));
    signals.extend(padding::scan_padding(data));
    signals.extend(tlv::scan_tlv(data));
    signals.extend(alignment::scan_alignment(data));
    signals.extend(chisq::scan_chi_square(data));
    signals.extend(compress::scan_compress_probe(data));
    signals.extend(entropy::entropy_map(
        data,
        entropy_block_size,
        stride.max(1),
    ));
    signals.sort_by_key(|s| s.region.offset);
    signals
}
