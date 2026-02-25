use crate::cfg::Cfg;
use petgraph::visit::IntoNodeReferences;
use std::collections::HashMap;

/// Cheap `Copy` handle into a [`SymbolInterner`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SymbolId(pub(crate) u32);

/// Per-function interner: maps `String` ↔ [`SymbolId`].
///
/// Built once from CFG node `defines`/`uses`, reused throughout analysis.
#[derive(Default)]
pub struct SymbolInterner {
    to_id: HashMap<String, SymbolId>,
    to_str: Vec<String>,
}

impl SymbolInterner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern a name, returning its stable [`SymbolId`].
    pub fn intern(&mut self, name: &str) -> SymbolId {
        if let Some(&id) = self.to_id.get(name) {
            return id;
        }
        let id = SymbolId(self.to_str.len() as u32);
        self.to_str.push(name.to_owned());
        self.to_id.insert(name.to_owned(), id);
        id
    }

    /// Look up a name without interning it.
    pub fn get(&self, name: &str) -> Option<SymbolId> {
        self.to_id.get(name).copied()
    }

    /// Resolve an id back to its string.
    pub fn resolve(&self, id: SymbolId) -> &str {
        &self.to_str[id.0 as usize]
    }

    /// Number of interned symbols.
    pub fn len(&self) -> usize {
        self.to_str.len()
    }

    /// Whether the interner is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.to_str.is_empty()
    }

    /// Build from a CFG: walk all nodes, intern every `defines`/`uses` string.
    pub fn from_cfg(cfg: &Cfg) -> Self {
        let mut interner = Self::new();
        for (_idx, info) in cfg.node_references() {
            if let Some(ref d) = info.defines {
                interner.intern(d);
            }
            for u in &info.uses {
                interner.intern(u);
            }
        }
        interner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intern_resolve_roundtrip() {
        let mut interner = SymbolInterner::new();
        let a = interner.intern("foo");
        let b = interner.intern("bar");
        let a2 = interner.intern("foo");

        assert_eq!(a, a2);
        assert_ne!(a, b);
        assert_eq!(interner.resolve(a), "foo");
        assert_eq!(interner.resolve(b), "bar");
    }

    #[test]
    fn get_returns_none_for_unknown() {
        let interner = SymbolInterner::new();
        assert!(interner.get("missing").is_none());
    }

    #[test]
    fn len_tracks_unique_symbols() {
        let mut interner = SymbolInterner::new();
        interner.intern("a");
        interner.intern("b");
        interner.intern("a"); // duplicate
        assert_eq!(interner.len(), 2);
    }
}
