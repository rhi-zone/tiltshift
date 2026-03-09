pub mod alignment;
pub mod bytecode;
pub mod chisq;
pub mod chunk;
pub mod compress;
pub mod entropy;
pub mod length_prefix;
pub mod magic;
pub mod ngram;
pub mod numeric;
pub mod offset_graph;
pub mod packed;
pub mod padding;
pub mod strings;
pub mod tlv;
pub mod varint;

use rayon::prelude::*;

use crate::corpus::Corpus;
use crate::types::Signal;

/// Run all signal extractors over `data` and return every signal found,
/// in offset order.
pub fn extract_all(data: &[u8], entropy_block_size: usize, corpus: &Corpus) -> Vec<Signal> {
    // Non-overlapping blocks: stride == block_size.  The old stride=block/4
    // gave 4× coverage and ballooned session caches into hundreds of MB for
    // large files (e.g. 24 MB → 378 K EntropyBlock signals at stride=64).
    let stride = entropy_block_size;

    // Each extractor is independent — run them in parallel via rayon.
    let extractors: Vec<Box<dyn Fn() -> Vec<Signal> + Send + Sync>> = vec![
        Box::new(|| magic::scan(data, corpus)),
        Box::new(|| strings::scan_null_terminated(data)),
        Box::new(|| length_prefix::scan_length_prefixed(data)),
        Box::new(|| chunk::scan_chunks(data)),
        Box::new(|| numeric::scan_numeric_landmarks(data)),
        Box::new(|| ngram::scan_ngrams(data)),
        Box::new(|| padding::scan_padding(data)),
        Box::new(|| tlv::scan_tlv(data)),
        Box::new(|| alignment::scan_alignment(data)),
        Box::new(|| chisq::scan_chi_square(data).into_iter().collect()),
        Box::new(|| compress::scan_compress_probe(data).into_iter().collect()),
        Box::new(|| varint::scan_varint(data)),
        Box::new(|| packed::scan_packed(data)),
        Box::new(|| offset_graph::scan_offset_graph(data)),
        Box::new(|| bytecode::scan_bytecode(data, 0)),
        Box::new(move || entropy::entropy_map(data, entropy_block_size, stride)),
    ];

    let mut signals: Vec<Signal> = extractors.into_par_iter().flat_map(|f| f()).collect();

    signals.sort_by_key(|s| s.region.offset);
    signals
}
