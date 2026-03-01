use memmap2::Mmap;
use std::fs::File;
use std::path::Path;

/// Memory-mapped view of a file.  The mapping is read-only and stays alive as
/// long as this struct is alive.
pub struct MappedFile {
    _file: File,
    map: Mmap,
}

impl MappedFile {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let file = File::open(path)?;
        // SAFETY: we hold the File open for the lifetime of the map and never
        // mutate the underlying bytes.
        let map = unsafe { Mmap::map(&file)? };
        Ok(Self { _file: file, map })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.map
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}
