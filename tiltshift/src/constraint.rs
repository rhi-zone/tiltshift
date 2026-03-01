//! Constraint propagation — derive annotations for unknown byte regions from
//! known signals.
//!
//! After the hypothesis engine identifies some byte ranges, gaps in the layout
//! (unknown regions) can be annotated by looking at what other signals say
//! about them: an in-bounds numeric value is a candidate pointer whose target
//! might be an important structure; an offset-graph edge points from a known
//! field to a destination that might sit in an unknown span.
//!
//! These annotations appear in the `analyze` LAYOUT output, giving the user a
//! head start on what each unknown region likely is.

use std::collections::HashSet;

use crate::types::{Region, Signal, SignalKind};

/// An annotation on a byte region derived from a referencing or neighboring signal.
pub struct Constraint {
    /// The byte range this constraint refers to.
    ///
    /// For pointer targets with no known extent, `len` is 1 (only the start
    /// offset is known).
    pub region: Region,
    /// Human-readable explanation of why this region is constrained.
    pub note: String,
}

/// Derive constraints from a flat list of signals.
///
/// Currently emits constraints from two sources:
///
/// - **[`SignalKind::NumericValue`]** `{ within_bounds: true }` — the stored
///   value is a plausible file offset, so the region it names is a candidate
///   pointer target.
///
/// - **[`SignalKind::OffsetGraph`]** — each unique destination address in
///   `sample_edges` is a pointer target in the largest connected component of
///   the pointer graph.
pub fn propagate(signals: &[Signal]) -> Vec<Constraint> {
    let mut out = Vec::new();

    for sig in signals {
        match &sig.kind {
            SignalKind::NumericValue {
                little_endian,
                value,
                within_bounds: true,
                ..
            } => {
                let target = *value as usize;
                let endian = if *little_endian { "le" } else { "be" };
                out.push(Constraint {
                    region: Region::new(target, 1),
                    note: format!(
                        "pointer target: u32{endian} field at 0x{:x} = 0x{value:x}",
                        sig.region.offset
                    ),
                });
            }

            SignalKind::OffsetGraph {
                pointer_width,
                little_endian,
                sample_edges,
                ..
            } => {
                let endian = if *little_endian { "le" } else { "be" };
                let width_bits = pointer_width * 8;
                let mut seen: HashSet<usize> = HashSet::new();
                for (src, dst) in sample_edges {
                    if seen.insert(*dst) {
                        out.push(Constraint {
                            region: Region::new(*dst, 1),
                            note: format!(
                                "pointer target: u{width_bits}{endian} edge from 0x{src:x}"
                            ),
                        });
                    }
                }
            }

            _ => {}
        }
    }

    out
}

/// Return all constraints whose target offset falls within `region`.
pub fn for_region<'a>(constraints: &'a [Constraint], region: &Region) -> Vec<&'a Constraint> {
    constraints
        .iter()
        .filter(|c| c.region.offset >= region.offset && c.region.offset < region.end())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Region, Signal, SignalKind};

    fn make_numeric(offset: usize, value: u32) -> Signal {
        Signal::new(
            Region::new(offset, 4),
            SignalKind::NumericValue {
                little_endian: true,
                value,
                file_size_match: false,
                power_of_two: false,
                within_bounds: true,
            },
            0.55,
            "test",
        )
    }

    #[test]
    fn numeric_value_emits_pointer_target() {
        let sig = make_numeric(0x28, 0x200);
        let constraints = propagate(&[sig]);
        assert_eq!(constraints.len(), 1);
        assert_eq!(constraints[0].region.offset, 0x200);
        assert!(constraints[0].note.contains("0x28"));
        assert!(constraints[0].note.contains("0x200"));
    }

    #[test]
    fn offset_graph_emits_unique_targets() {
        let sig = Signal::new(
            Region::new(0, 100),
            SignalKind::OffsetGraph {
                pointer_width: 4,
                little_endian: true,
                candidate_count: 5,
                component_nodes: 3,
                component_edges: 2,
                pointer_density: 0.1,
                sample_edges: vec![(0x10, 0x40), (0x14, 0x80), (0x18, 0x40)],
            },
            0.70,
            "test",
        );
        let constraints = propagate(&[sig]);
        // 0x40 appears twice as target but should only emit once.
        assert_eq!(constraints.len(), 2);
        let targets: Vec<usize> = constraints.iter().map(|c| c.region.offset).collect();
        assert!(targets.contains(&0x40));
        assert!(targets.contains(&0x80));
    }

    #[test]
    fn for_region_filters_correctly() {
        let constraints = vec![
            Constraint {
                region: Region::new(0x40, 1),
                note: "a".to_string(),
            },
            Constraint {
                region: Region::new(0x80, 1),
                note: "b".to_string(),
            },
            Constraint {
                region: Region::new(0x100, 1),
                note: "c".to_string(),
            },
        ];
        let span = Region::new(0x30, 0x80); // [0x30, 0xb0)
        let found = for_region(&constraints, &span);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].region.offset, 0x40);
        assert_eq!(found[1].region.offset, 0x80);
    }

    #[test]
    fn numeric_value_without_within_bounds_emits_nothing() {
        let sig = Signal::new(
            Region::new(0x28, 4),
            SignalKind::NumericValue {
                little_endian: true,
                value: 0x200,
                file_size_match: false,
                power_of_two: false,
                within_bounds: false,
            },
            0.30,
            "test",
        );
        let constraints = propagate(&[sig]);
        assert!(constraints.is_empty());
    }
}
