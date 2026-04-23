// ── populate_node_meta + CrossFileNodeMeta tests ─────────────────────────

#[cfg(test)]
mod cross_file_tests {
    use super::super::*;
    use crate::cfg::{AstMeta, BinOp, CallMeta, EdgeKind, NodeInfo, StmtKind, TaintMeta};
    use crate::labels::DataLabel;

    use petgraph::prelude::*;
    use smallvec::smallvec;

    fn make_test_cfg() -> crate::cfg::Cfg {
        let mut cfg = Graph::new();
        let n0 = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            ast: AstMeta {
                span: (0, 10),
                ..Default::default()
            },
            taint: TaintMeta {
                labels: smallvec![DataLabel::Source(crate::labels::Cap::all())],
                defines: Some("x".into()),
                ..Default::default()
            },
            call: CallMeta::default(),
            bin_op: Some(BinOp::Add),
            ..Default::default()
        });
        let n1 = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            ast: AstMeta {
                span: (10, 20),
                ..Default::default()
            },
            taint: TaintMeta {
                defines: Some("y".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        cfg.add_edge(n0, n1, EdgeKind::Seq);
        cfg
    }

    fn make_body_referencing_nodes(n0: NodeIndex, n1: NodeIndex) -> CalleeSsaBody {
        CalleeSsaBody {
            ssa: SsaBody {
                blocks: vec![SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![
                        SsaInst {
                            value: SsaValue(0),
                            op: SsaOp::Source,
                            cfg_node: n0,
                            var_name: Some("x".into()),
                            span: (0, 5),
                        },
                        SsaInst {
                            value: SsaValue(1),
                            op: SsaOp::Assign(smallvec![SsaValue(0)]),
                            cfg_node: n1,
                            var_name: Some("y".into()),
                            span: (5, 10),
                        },
                    ],
                    terminator: Terminator::Return(Some(SsaValue(1))),
                    preds: smallvec![],
                    succs: smallvec![],
                }],
                entry: BlockId(0),
                value_defs: vec![
                    ValueDef {
                        var_name: Some("x".into()),
                        cfg_node: n0,
                        block: BlockId(0),
                    },
                    ValueDef {
                        var_name: Some("y".into()),
                        cfg_node: n1,
                        block: BlockId(0),
                    },
                ],
                cfg_node_map: std::collections::HashMap::new(),
                exception_edges: vec![],
            },
            opt: crate::ssa::OptimizeResult {
                const_values: std::collections::HashMap::new(),
                type_facts: crate::ssa::type_facts::TypeFactResult {
                    facts: std::collections::HashMap::new(),
                },
                alias_result: crate::ssa::alias::BaseAliasResult::empty(),
                points_to: crate::ssa::heap::PointsToResult::empty(),
                module_aliases: std::collections::HashMap::new(),
                branches_pruned: 0,
                copies_eliminated: 0,
                dead_defs_removed: 0,
            },
            param_count: 0,
            node_meta: std::collections::HashMap::new(),
            body_graph: None,
        }
    }

    #[test]
    fn populate_node_meta_extracts_bin_op_and_labels() {
        let cfg = make_test_cfg();
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let mut body = make_body_referencing_nodes(n0, n1);

        assert!(body.node_meta.is_empty());
        let ok = populate_node_meta(&mut body, &cfg);
        assert!(ok, "should succeed for valid nodes");

        assert_eq!(body.node_meta.len(), 2);

        // Node 0: has bin_op=Add and Source label
        let meta0 = &body.node_meta[&0];
        assert_eq!(meta0.info.bin_op, Some(BinOp::Add));
        assert_eq!(meta0.info.taint.labels.len(), 1);
        assert!(matches!(meta0.info.taint.labels[0], DataLabel::Source(_)));
        // Full NodeInfo round-trip: span, defines, and kind are preserved.
        assert_eq!(meta0.info.ast.span, (0, 10));
        assert_eq!(meta0.info.taint.defines.as_deref(), Some("x"));

        // Node 1: no bin_op, no labels
        let meta1 = &body.node_meta[&1];
        assert_eq!(meta1.info.bin_op, None);
        assert!(meta1.info.taint.labels.is_empty());
        assert_eq!(meta1.info.taint.defines.as_deref(), Some("y"));
    }

    #[test]
    fn populate_node_meta_fails_on_invalid_node() {
        let cfg = make_test_cfg(); // only has 2 nodes (0, 1)
        let bad_node = NodeIndex::new(999);
        let n0 = NodeIndex::new(0);

        let mut body = make_body_referencing_nodes(n0, bad_node);

        let ok = populate_node_meta(&mut body, &cfg);
        assert!(!ok, "should fail for out-of-bounds NodeIndex");
    }

    #[test]
    fn populate_node_meta_idempotent() {
        let cfg = make_test_cfg();
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let mut body = make_body_referencing_nodes(n0, n1);

        populate_node_meta(&mut body, &cfg);
        let first_pass = body.node_meta.clone();

        populate_node_meta(&mut body, &cfg);
        assert_eq!(
            body.node_meta, first_pass,
            "second call should be idempotent"
        );
    }

    #[test]
    fn cross_file_node_meta_default() {
        let meta = CrossFileNodeMeta::default();
        assert_eq!(meta.info.bin_op, None);
        assert!(meta.info.taint.labels.is_empty());
    }

    // ── rebuild_body_graph ──────────────────────────────────────────────

    #[test]
    fn rebuild_body_graph_synthesizes_proxy_cfg() {
        let cfg = make_test_cfg();
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let mut body = make_body_referencing_nodes(n0, n1);
        populate_node_meta(&mut body, &cfg);
        // Simulate the indexed-scan load: body_graph is skipped by serde.
        body.body_graph = None;

        let rebuilt = rebuild_body_graph(&mut body);
        assert!(rebuilt, "rebuild should install a fresh graph");
        let graph = body.body_graph.as_ref().expect("graph rebuilt");
        assert_eq!(graph.node_count(), 2);
        let info0 = &graph[n0];
        assert_eq!(info0.bin_op, Some(BinOp::Add));
        assert_eq!(info0.taint.labels.len(), 1);
        assert!(matches!(info0.taint.labels[0], DataLabel::Source(_)));
    }

    #[test]
    fn rebuild_body_graph_is_idempotent() {
        let cfg = make_test_cfg();
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let mut body = make_body_referencing_nodes(n0, n1);
        populate_node_meta(&mut body, &cfg);
        body.body_graph = None;

        assert!(rebuild_body_graph(&mut body));
        assert!(!rebuild_body_graph(&mut body), "second call must no-op");
    }

    #[test]
    fn rebuild_body_graph_noop_without_meta() {
        // Intra-file body: node_meta empty, body_graph comes from pass 1.
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let mut body = make_body_referencing_nodes(n0, n1);
        assert!(body.node_meta.is_empty());
        assert!(body.body_graph.is_none());
        assert!(!rebuild_body_graph(&mut body));
        assert!(body.body_graph.is_none());
    }
}

#[cfg(test)]
mod inline_cache_epoch_tests {
    //! Hooks for cross-file SCC joint fixed-point iteration.
    //!
    //! These do not exercise the full inline pipeline — they lock down the
    //! semantic contract of [`inline_cache_clear_epoch`] and
    //! [`inline_cache_fingerprint`] so the SCC orchestrator can rely on:
    //!
    //! * `clear_epoch` drops every entry, leaving the cache empty.
    //! * `fingerprint` is deterministic across equivalent caches (same
    //!   keys → same bytes).  Two caches with identical entries produce
    //!   identical fingerprints regardless of insertion order.
    //! * `fingerprint` changes when return caps change — the signal the
    //!   orchestrator will use to detect inline-cache convergence.

    use super::super::*;
    use crate::labels::Cap;
    use crate::symbol::FuncKey;
    use crate::taint::domain::VarTaint;
    use smallvec::SmallVec;

    fn key(name: &str) -> FuncKey {
        FuncKey {
            name: name.into(),
            ..Default::default()
        }
    }

    fn sig() -> ArgTaintSig {
        ArgTaintSig(SmallVec::new())
    }

    fn shape(caps_bits: u16) -> CachedInlineShape {
        CachedInlineShape(Some(ReturnShape {
            caps: Cap::from_bits_retain(caps_bits),
            internal_origins: SmallVec::new(),
            param_provenance: 0,
            receiver_provenance: false,
            uses_summary: false,
        }))
    }

    #[test]
    fn clear_epoch_drops_all_entries() {
        let mut c: InlineCache = HashMap::new();
        c.insert((key("a"), sig()), shape(1));
        c.insert((key("b"), sig()), shape(2));
        assert_eq!(c.len(), 2);

        inline_cache_clear_epoch(&mut c);
        assert!(c.is_empty());
    }

    #[test]
    fn fingerprint_is_order_independent() {
        let mut a: InlineCache = HashMap::new();
        a.insert((key("alpha"), sig()), shape(3));
        a.insert((key("beta"), sig()), shape(5));

        let mut b: InlineCache = HashMap::new();
        b.insert((key("beta"), sig()), shape(5));
        b.insert((key("alpha"), sig()), shape(3));

        assert_eq!(inline_cache_fingerprint(&a), inline_cache_fingerprint(&b));
    }

    #[test]
    fn fingerprint_changes_when_return_caps_change() {
        let mut c: InlineCache = HashMap::new();
        c.insert((key("f"), sig()), shape(0));
        let before = inline_cache_fingerprint(&c);

        c.insert((key("f"), sig()), shape(1));
        let after = inline_cache_fingerprint(&c);

        assert_ne!(before, after, "cap refinement must change fingerprint");
    }

    #[test]
    fn fingerprint_tracks_missing_return_taint_as_zero() {
        // A cached miss (no return taint) fingerprints as zero caps so
        // two converged iterations both producing "no return taint" are
        // recognised as equal.
        let mut c: InlineCache = HashMap::new();
        c.insert((key("f"), sig()), CachedInlineShape(None));
        let fp = inline_cache_fingerprint(&c);
        assert_eq!(*fp.get(&(key("f"), sig())).unwrap(), 0);
    }

    // ── apply_cached_shape: origin re-attribution (Phase 5) ─────────────

    use crate::labels::SourceKind;
    use petgraph::graph::NodeIndex;

    fn origin_at(node: usize, kind: SourceKind, span: Option<(usize, usize)>) -> TaintOrigin {
        TaintOrigin {
            node: NodeIndex::new(node),
            source_kind: kind,
            source_span: span,
        }
    }

    #[test]
    fn apply_reattributes_param_origins_per_call_site() {
        // Shared cached shape: cap bit set, Param(0) marked as provenance source.
        let cached = CachedInlineShape(Some(ReturnShape {
            caps: Cap::SHELL_ESCAPE,
            internal_origins: SmallVec::new(),
            param_provenance: 1u64 << 0,
            receiver_provenance: false,
            uses_summary: true,
        }));

        // Caller A: argument carries an env-source origin.
        let mut state_a = SsaTaintState::initial();
        state_a.set(
            SsaValue(1),
            VarTaint {
                caps: Cap::SHELL_ESCAPE,
                origins: SmallVec::from_vec(vec![origin_at(
                    10,
                    SourceKind::EnvironmentConfig,
                    Some((100, 120)),
                )]),
                uses_summary: false,
            },
        );
        let args_a: Vec<SmallVec<[SsaValue; 2]>> = vec![SmallVec::from_vec(vec![SsaValue(1)])];
        let res_a = apply_cached_shape(&cached, &args_a, &None, &state_a, NodeIndex::new(200));
        let vt_a = res_a.return_taint.expect("apply a");
        assert_eq!(vt_a.origins.len(), 1);
        assert_eq!(vt_a.origins[0].source_kind, SourceKind::EnvironmentConfig);
        assert_eq!(vt_a.origins[0].source_span, Some((100, 120)));

        // Caller B: same caps, different origin (filesystem read).
        let mut state_b = SsaTaintState::initial();
        state_b.set(
            SsaValue(2),
            VarTaint {
                caps: Cap::SHELL_ESCAPE,
                origins: SmallVec::from_vec(vec![origin_at(
                    20,
                    SourceKind::FileSystem,
                    Some((300, 320)),
                )]),
                uses_summary: false,
            },
        );
        let args_b: Vec<SmallVec<[SsaValue; 2]>> = vec![SmallVec::from_vec(vec![SsaValue(2)])];
        let res_b = apply_cached_shape(&cached, &args_b, &None, &state_b, NodeIndex::new(201));
        let vt_b = res_b.return_taint.expect("apply b");
        assert_eq!(vt_b.origins.len(), 1);
        assert_eq!(
            vt_b.origins[0].source_kind,
            SourceKind::FileSystem,
            "second caller must see its own source, not caller A's cached origin"
        );
        assert_eq!(vt_b.origins[0].source_span, Some((300, 320)));
    }

    #[test]
    fn apply_remaps_internal_origins_to_call_site() {
        // Cached shape with a single callee-internal origin.
        let internal_origin = TaintOrigin {
            node: NodeIndex::end(), // placeholder written by extract
            source_kind: SourceKind::UserInput,
            source_span: Some((55, 77)),
        };
        let mut internal_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
        internal_origins.push(internal_origin);
        let cached = CachedInlineShape(Some(ReturnShape {
            caps: Cap::HTML_ESCAPE,
            internal_origins,
            param_provenance: 0,
            receiver_provenance: false,
            uses_summary: true,
        }));

        let state = SsaTaintState::initial();
        let args: Vec<SmallVec<[SsaValue; 2]>> = vec![];
        let call_site = NodeIndex::new(777);
        let res = apply_cached_shape(&cached, &args, &None, &state, call_site);
        let vt = res.return_taint.expect("apply");
        assert_eq!(vt.origins.len(), 1);
        assert_eq!(vt.origins[0].node, call_site);
        assert_eq!(vt.origins[0].source_span, Some((55, 77)));
    }
}

#[cfg(test)]
mod binding_key_tests {
    use super::super::*;
    use crate::taint::domain::VarTaint;
    use smallvec::smallvec;
    use std::collections::HashMap;

    // ── PartialEq / Hash ───────────────────────────────────────────────

    #[test]
    fn same_name_both_none_match() {
        let a = BindingKey::new("x");
        let b = BindingKey::new("x");
        assert_eq!(a, b);
        assert!(a.matches(&b));
    }

    #[test]
    fn same_name_one_none_one_some_matches() {
        let none_key = BindingKey::new("x");
        let some_key = BindingKey::with_body_id("x", 1);
        // Standard PartialEq: different (body_id differs)
        assert_ne!(none_key, some_key);
        // Body-id-aware matching: None wildcard
        assert!(none_key.matches(&some_key));
        assert!(some_key.matches(&none_key));
    }

    #[test]
    fn same_name_same_body_id_matches() {
        let a = BindingKey::with_body_id("x", 1);
        let b = BindingKey::with_body_id("x", 1);
        assert_eq!(a, b);
        assert!(a.matches(&b));
    }

    #[test]
    fn same_name_different_body_id_no_match() {
        let a = BindingKey::with_body_id("x", 1);
        let b = BindingKey::with_body_id("x", 2);
        assert_ne!(a, b);
        assert!(!a.matches(&b));
    }

    #[test]
    fn different_name_no_match() {
        // None body_id
        assert!(!BindingKey::new("x").matches(&BindingKey::new("y")));
        // Same body_id
        assert!(!BindingKey::with_body_id("x", 1).matches(&BindingKey::with_body_id("y", 1)));
        // Mixed
        assert!(!BindingKey::new("x").matches(&BindingKey::with_body_id("y", 1)));
    }

    // ── seed_lookup ────────────────────────────────────────────────────

    fn taint(caps: u16) -> VarTaint {
        VarTaint {
            caps: Cap::from_bits_truncate(caps),
            origins: smallvec![],
            uses_summary: false,
        }
    }

    #[test]
    fn seed_lookup_exact_match() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::new("x"), taint(1));
        let key = BindingKey::new("x");
        assert!(seed_lookup(&seed, &key).is_some());
        assert_eq!(
            seed_lookup(&seed, &key).unwrap().caps,
            Cap::from_bits_truncate(1)
        );
    }

    #[test]
    fn seed_lookup_none_finds_none() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::new("x"), taint(1));
        // Query with None body_id → exact match (both None)
        let key = BindingKey::new("x");
        assert!(seed_lookup(&seed, &key).is_some());
    }

    #[test]
    fn seed_lookup_some_falls_back_to_none() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::new("x"), taint(1)); // body_id=None
        // Query with Some(1) → exact miss, but fallback matches None via wildcard
        let key = BindingKey::with_body_id("x", 1);
        assert!(seed_lookup(&seed, &key).is_some());
    }

    #[test]
    fn seed_lookup_none_falls_back_to_some() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::with_body_id("x", 1), taint(1)); // body_id=Some(1)
        // Query with None → exact miss, but fallback matches via wildcard
        let key = BindingKey::new("x");
        assert!(seed_lookup(&seed, &key).is_some());
    }

    #[test]
    fn seed_lookup_prefers_exact_over_wildcard() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::new("x"), taint(1)); // None → caps=1
        seed.insert(BindingKey::with_body_id("x", 1), taint(2)); // Some(1) → caps=2
        // Exact match for Some(1) returns caps=2
        let key = BindingKey::with_body_id("x", 1);
        assert_eq!(
            seed_lookup(&seed, &key).unwrap().caps,
            Cap::from_bits_truncate(2)
        );
    }

    #[test]
    fn seed_lookup_different_body_ids_distinct() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::with_body_id("x", 1), taint(1));
        seed.insert(BindingKey::with_body_id("x", 2), taint(2));
        // Query for body_id=1 → exact match
        let key1 = BindingKey::with_body_id("x", 1);
        assert_eq!(
            seed_lookup(&seed, &key1).unwrap().caps,
            Cap::from_bits_truncate(1)
        );
        // Query for body_id=2 → exact match
        let key2 = BindingKey::with_body_id("x", 2);
        assert_eq!(
            seed_lookup(&seed, &key2).unwrap().caps,
            Cap::from_bits_truncate(2)
        );
        // Query for body_id=3 → no exact match, no None entry, no wildcard → None
        let key3 = BindingKey::with_body_id("x", 3);
        assert!(seed_lookup(&seed, &key3).is_none());
    }

    #[test]
    fn seed_lookup_miss_different_name() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::new("x"), taint(1));
        let key = BindingKey::new("y");
        assert!(seed_lookup(&seed, &key).is_none());
    }

    /// When writers have tagged the same name with different body_ids
    /// (e.g. JS/TS two-level solve's `combined_exit` after several
    /// functions have contributed), a reader using the wildcard form
    /// (`BindingKey::new(name)` → `body_id = None`) must see the
    /// **union** of all matching entries.  Returning an arbitrary
    /// first-match would be non-deterministic and could silently cross-
    /// link taint from an unrelated scope while dropping real taint.
    #[test]
    fn seed_lookup_wildcard_unions_matches_across_body_ids() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::with_body_id("x", 1), taint(0b0001));
        seed.insert(BindingKey::with_body_id("x", 2), taint(0b0010));
        seed.insert(BindingKey::with_body_id("x", 3), taint(0b0100));
        // Unrelated name must not pollute the union.
        seed.insert(BindingKey::with_body_id("y", 1), taint(0b1000));

        let wildcard = BindingKey::new("x");
        let looked = seed_lookup(&seed, &wildcard).expect("wildcard hits");
        assert_eq!(looked.caps, Cap::from_bits_truncate(0b0111));
    }

    /// Exact body_id lookup must keep its O(1) semantics and not be
    /// affected by the wildcard-union slow path.
    #[test]
    fn seed_lookup_exact_body_id_ignores_siblings() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::with_body_id("x", 1), taint(0b0001));
        seed.insert(BindingKey::with_body_id("x", 2), taint(0b0010));
        let key = BindingKey::with_body_id("x", 1);
        let looked = seed_lookup(&seed, &key).expect("exact match");
        assert_eq!(looked.caps, Cap::from_bits_truncate(0b0001));
    }

    // ── join_seed_maps ─────────────────────────────────────────────────

    #[test]
    fn join_seed_maps_does_not_merge_different_body_ids() {
        let mut a = HashMap::new();
        a.insert(BindingKey::with_body_id("x", 1), taint(1));
        let mut b = HashMap::new();
        b.insert(BindingKey::with_body_id("x", 2), taint(2));
        let joined = join_seed_maps(&a, &b);
        // Both entries preserved (different body_ids → different keys)
        assert_eq!(joined.len(), 2);
        assert_eq!(
            joined.get(&BindingKey::with_body_id("x", 1)).unwrap().caps,
            Cap::from_bits_truncate(1)
        );
        assert_eq!(
            joined.get(&BindingKey::with_body_id("x", 2)).unwrap().caps,
            Cap::from_bits_truncate(2)
        );
    }

    #[test]
    fn join_seed_maps_merges_same_body_id() {
        let mut a = HashMap::new();
        a.insert(BindingKey::with_body_id("x", 1), taint(1));
        let mut b = HashMap::new();
        b.insert(BindingKey::with_body_id("x", 1), taint(2));
        let joined = join_seed_maps(&a, &b);
        assert_eq!(joined.len(), 1);
        let caps = joined.get(&BindingKey::with_body_id("x", 1)).unwrap().caps;
        // OR of caps 1 and 2
        assert!(caps.contains(Cap::from_bits_truncate(1)));
        assert!(caps.contains(Cap::from_bits_truncate(2)));
    }

    // ── filter_seed_to_toplevel ────────────────────────────────────────

    #[test]
    fn filter_seed_retains_matching_body_ids() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::with_body_id("x", 1), taint(1));
        seed.insert(BindingKey::with_body_id("y", 2), taint(2));

        // Toplevel keys with None body_id should match any body_id (wildcard)
        let mut toplevel = HashSet::new();
        toplevel.insert(BindingKey::new("x")); // None matches body_id=1
        let filtered = filter_seed_to_toplevel(&seed, &toplevel);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key(&BindingKey::with_body_id("x", 1)));
    }

    #[test]
    fn filter_seed_excludes_non_toplevel() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::new("x"), taint(1));
        seed.insert(BindingKey::new("y"), taint(2));

        let mut toplevel = HashSet::new();
        toplevel.insert(BindingKey::new("x"));
        let filtered = filter_seed_to_toplevel(&seed, &toplevel);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key(&BindingKey::new("x")));
    }
}

#[cfg(test)]
mod worklist_tests {
    use std::collections::{HashSet, VecDeque};

    /// Simulate the O(1) worklist membership pattern from run_ssa_taint_internal.
    /// Verifies that the HashSet stays in sync with the VecDeque.
    fn worklist_push(wl: &mut VecDeque<usize>, in_wl: &mut HashSet<usize>, idx: usize) -> bool {
        if in_wl.insert(idx) {
            wl.push_back(idx);
            true
        } else {
            false
        }
    }

    fn worklist_pop(wl: &mut VecDeque<usize>, in_wl: &mut HashSet<usize>) -> Option<usize> {
        let val = wl.pop_front()?;
        in_wl.remove(&val);
        Some(val)
    }

    #[test]
    fn duplicate_enqueue_produces_single_entry() {
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();
        assert!(worklist_push(&mut wl, &mut in_wl, 0));
        assert!(!worklist_push(&mut wl, &mut in_wl, 0)); // duplicate
        assert_eq!(wl.len(), 1);
        assert_eq!(in_wl.len(), 1);
    }

    #[test]
    fn pop_removes_from_set() {
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();
        worklist_push(&mut wl, &mut in_wl, 5);
        worklist_push(&mut wl, &mut in_wl, 10);
        let val = worklist_pop(&mut wl, &mut in_wl);
        assert_eq!(val, Some(5));
        assert!(!in_wl.contains(&5));
        assert!(in_wl.contains(&10));
    }

    #[test]
    fn re_enqueue_after_pop() {
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();
        worklist_push(&mut wl, &mut in_wl, 0);
        let _ = worklist_pop(&mut wl, &mut in_wl);
        // After popping, we should be able to re-enqueue
        assert!(worklist_push(&mut wl, &mut in_wl, 0));
        assert_eq!(wl.len(), 1);
    }

    #[test]
    fn empty_worklist() {
        let mut wl: VecDeque<usize> = VecDeque::new();
        let mut in_wl: HashSet<usize> = HashSet::new();
        assert_eq!(worklist_pop(&mut wl, &mut in_wl), None);
        assert!(in_wl.is_empty());
    }

    #[test]
    fn self_loop_pattern() {
        // Simulate a block that re-enqueues itself
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();
        worklist_push(&mut wl, &mut in_wl, 0);

        let block = worklist_pop(&mut wl, &mut in_wl).unwrap();
        assert_eq!(block, 0);
        // Re-enqueue self (simulating state change)
        worklist_push(&mut wl, &mut in_wl, 0);
        // Also enqueue successor
        worklist_push(&mut wl, &mut in_wl, 1);
        assert_eq!(wl.len(), 2);
    }

    #[test]
    fn cycle_with_repeated_discovery() {
        // Simulate cycle: 0→1→2→0 with multiple state propagations
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();
        worklist_push(&mut wl, &mut in_wl, 0);

        let mut iterations = 0;
        while let Some(block) = worklist_pop(&mut wl, &mut in_wl) {
            iterations += 1;
            if iterations > 10 {
                break; // safety net
            }
            let succ = (block + 1) % 3;
            // Only re-enqueue if "state changed" (simulate with iteration limit)
            if iterations < 6 {
                worklist_push(&mut wl, &mut in_wl, succ);
            }
        }
        assert!(iterations <= 10, "worklist should terminate");
        assert!(wl.is_empty());
        assert!(in_wl.is_empty());
    }

    #[test]
    fn dense_successors_no_duplicates() {
        // Many successors, some repeated — old O(n) contains() would be slow here
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();

        // Seed with one node
        worklist_push(&mut wl, &mut in_wl, 0);
        let _ = worklist_pop(&mut wl, &mut in_wl);

        // Try to add 100 successors, with many duplicates
        let mut total_enqueued = 0;
        for i in 0..100 {
            let succ = i % 10; // only 10 unique blocks
            if worklist_push(&mut wl, &mut in_wl, succ) {
                total_enqueued += 1;
            }
        }
        assert_eq!(total_enqueued, 10); // only 10 unique blocks enqueued
        assert_eq!(wl.len(), 10);
        assert_eq!(in_wl.len(), 10);
    }

    #[test]
    fn set_and_deque_stay_in_sync_throughout() {
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();

        // Push, pop, re-push cycle
        for i in 0..20 {
            worklist_push(&mut wl, &mut in_wl, i);
        }
        assert_eq!(wl.len(), in_wl.len());

        for _ in 0..10 {
            worklist_pop(&mut wl, &mut in_wl);
        }
        assert_eq!(wl.len(), in_wl.len());
        assert_eq!(wl.len(), 10);

        // Re-push some previously popped
        for i in 0..5 {
            worklist_push(&mut wl, &mut in_wl, i);
        }
        assert_eq!(wl.len(), in_wl.len());
        assert_eq!(wl.len(), 15);

        // Drain completely
        while worklist_pop(&mut wl, &mut in_wl).is_some() {}
        assert!(wl.is_empty());
        assert!(in_wl.is_empty());
    }
}

#[cfg(test)]
mod primary_sink_location_tests {
    //! Regression guard for the primary sink-location attribution contract:
    //! a [`SinkSite`] carried on an [`SsaFuncSummary`] must propagate
    //! unchanged through summary resolution →
    //! [`SsaTaintEvent::primary_sink_site`] →
    //! [`crate::taint::Finding::primary_location`].
    //!
    //! The test is deliberately low-level — it wires up synthetic SSA and
    //! drives the three emission stages directly — so any future refactor
    //! that drops the site on the floor between stages fails here rather
    //! than only at the corpus/benchmark layer.
    use super::super::*;
    use crate::cfg::{AstMeta, CallMeta, Cfg, NodeInfo, StmtKind, TaintMeta};
    use crate::labels::{Cap, SourceKind};
    use crate::summary::SinkSite;
    use crate::summary::ssa_summary::SsaFuncSummary;
    use crate::taint::domain::TaintOrigin;
    use petgraph::graph::NodeIndex;
    use petgraph::prelude::*;
    use smallvec::smallvec;
    use std::collections::HashMap;

    /// Build a caller CFG that models `sink(source())`: two nodes, where
    /// the sink node carries `callee = "dangerous_exec"` so
    /// [`reconstruct_flow_path`] can name the sink.
    fn caller_cfg() -> (Cfg, NodeIndex, NodeIndex) {
        let mut cfg = Graph::new();
        let source = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            ast: AstMeta {
                span: (0, 5),
                ..Default::default()
            },
            taint: TaintMeta::default(),
            call: CallMeta::default(),
            ..Default::default()
        });
        let sink = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (10, 30),
                ..Default::default()
            },
            taint: TaintMeta::default(),
            call: CallMeta {
                callee: Some("dangerous_exec".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        (cfg, source, sink)
    }

    /// Build an SSA body for `v0 = source(); v1 = dangerous_exec(v0); ret`.
    fn caller_body(source_node: NodeIndex, sink_node: NodeIndex) -> SsaBody {
        let mut cfg_node_map = HashMap::new();
        cfg_node_map.insert(source_node, SsaValue(0));
        cfg_node_map.insert(sink_node, SsaValue(1));
        SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Source,
                        cfg_node: source_node,
                        var_name: Some("x".into()),
                        span: (0, 5),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Call {
                            callee: "dangerous_exec".into(),
                            args: vec![smallvec![SsaValue(0)]],
                            receiver: None,
                        },
                        cfg_node: sink_node,
                        var_name: None,
                        span: (10, 30),
                    },
                ],
                terminator: Terminator::Return(None),
                preds: smallvec![],
                succs: smallvec![],
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("x".into()),
                    cfg_node: source_node,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: None,
                    cfg_node: sink_node,
                    block: BlockId(0),
                },
            ],
            cfg_node_map,
            exception_edges: vec![],
        }
    }

    /// Locks in the end-to-end contract that a SinkSite on an
    /// SsaFuncSummary surfaces verbatim as `Finding.primary_location`.
    ///
    /// If this fails, something on the summary→event→finding path
    /// (`pick_primary_sink_sites`, `emit_ssa_taint_events`, or
    /// `ssa_events_to_findings`) has silently stopped forwarding
    /// coordinates.  Fixing that path — not this test — is the right
    /// response.
    #[test]
    fn ssa_summary_sinksite_surfaces_as_finding_primary_location() {
        let (cfg, source_node, sink_node) = caller_cfg();
        let ssa = caller_body(source_node, sink_node);

        // Synthetic summary: parameter 0 reaches a SHELL_ESCAPE sink inside
        // the callee at "other.rs":42:10.
        let site = SinkSite {
            file_rel: "other.rs".into(),
            line: 42,
            col: 10,
            snippet: "Command::new(cmd).status()".into(),
            cap: Cap::SHELL_ESCAPE,
        };
        let summary = SsaFuncSummary {
            param_to_sink: vec![(0usize, smallvec![site.clone()])],
            ..Default::default()
        };

        // Drive the three emission stages with the summary's own
        // `param_to_sink` — that is what summary resolution feeds in the
        // real pipeline.
        let tainted: Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)> = vec![(
            SsaValue(0),
            Cap::SHELL_ESCAPE,
            smallvec![TaintOrigin {
                node: source_node,
                source_kind: SourceKind::EnvironmentConfig,
                source_span: None,
            }],
        )];
        let call_inst = &ssa.blocks[0].body[1];
        let primary_sites = pick_primary_sink_sites(
            call_inst,
            &tainted,
            Cap::SHELL_ESCAPE,
            &summary.param_to_sink,
        );
        assert_eq!(
            primary_sites.len(),
            1,
            "summary site must survive pick filter (line != 0, cap ∩ sink_caps ≠ ∅)",
        );

        let mut events = Vec::new();
        emit_ssa_taint_events(
            &mut events,
            sink_node,
            tainted.clone(),
            Cap::SHELL_ESCAPE,
            /* all_validated */ false,
            /* guard_kind   */ None,
            /* uses_summary */ true,
            primary_sites,
        );
        assert_eq!(events.len(), 1, "single site → single event");
        let event_site = events[0]
            .primary_sink_site
            .as_ref()
            .expect("event must carry the primary SinkSite");
        assert_eq!(
            (
                event_site.file_rel.as_str(),
                event_site.line,
                event_site.col,
            ),
            ("other.rs", 42, 10),
        );

        let findings = ssa_events_to_findings(&events, &ssa, &cfg);
        assert_eq!(findings.len(), 1);
        let loc = findings[0]
            .primary_location
            .as_ref()
            .expect("Finding.primary_location must be populated from SinkSite");
        assert_eq!(loc.file_rel, "other.rs");
        assert_eq!(loc.line, 42);
        assert_eq!(loc.col, 10);
        assert_eq!(loc.snippet, "Command::new(cmd).status()");
    }
}

#[cfg(test)]
mod goto_succ_propagation_tests {
    //! Regression guard for the 3-successor Goto collapse in
    //! `src/ssa/lower.rs` (see `three_successor_collapse_produces_goto`).
    //!
    //! Lowering collapses ≥3-successor blocks to `Terminator::Goto(first)`
    //! but preserves the full successor list on `block.succs`. Flow
    //! consumers (this module's `compute_succ_states`, SCCP's
    //! `process_terminator`) must treat `block.succs` as authoritative.
    //! Without that, taint exits only through the first successor and all
    //! downstream blocks on the other edges silently drop it.
    use super::super::*;
    use crate::cfg::Cfg;
    use crate::state::symbol::SymbolInterner;
    use petgraph::Graph;
    use smallvec::smallvec;

    #[test]
    fn goto_propagates_to_every_succ_on_three_way_collapse() {
        // Build a block with Terminator::Goto(1) but succs = [1, 2, 3] — the
        // shape lowering emits for a 3-way fanout.
        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            body: vec![],
            terminator: Terminator::Goto(BlockId(1)),
            preds: smallvec![],
            succs: smallvec![BlockId(1), BlockId(2), BlockId(3)],
        };

        let ssa = SsaBody {
            blocks: vec![block.clone()],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: std::collections::HashMap::new(),
            exception_edges: vec![],
        };

        let cfg: Cfg = Graph::new();
        let interner = SymbolInterner::new();
        let local_summaries: FuncSummaries = std::collections::HashMap::new();

        let transfer = SsaTaintTransfer {
            lang: Lang::JavaScript,
            namespace: "",
            interner: &interner,
            local_summaries: &local_summaries,
            global_summaries: None,
            interop_edges: &[],
            global_seed: None,
            const_values: None,
            type_facts: None,
            ssa_summaries: None,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases: None,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
        };

        // A non-bottom exit state — the test only cares that *every* succ
        // receives a clone of it, so any distinguishable state works.
        let mut exit_state = SsaTaintState::initial();
        exit_state.values.push((
            SsaValue(42),
            VarTaint {
                caps: crate::labels::Cap::all(),
                origins: smallvec::SmallVec::new(),
                uses_summary: false,
            },
        ));

        let succ_states = compute_succ_states(&block, &cfg, &ssa, &transfer, &exit_state);

        assert_eq!(
            succ_states.len(),
            3,
            "Goto with 3 succs must propagate to all 3 successors, got {:?}",
            succ_states.iter().map(|(b, _)| *b).collect::<Vec<_>>()
        );

        let targets: Vec<BlockId> = succ_states.iter().map(|(b, _)| *b).collect();
        assert_eq!(targets, vec![BlockId(1), BlockId(2), BlockId(3)]);

        for (bid, state) in &succ_states {
            assert!(
                state.values.iter().any(|(v, _)| *v == SsaValue(42)),
                "succ {:?} did not receive the exit state taint",
                bid
            );
        }
    }

    #[test]
    fn goto_single_successor_still_works() {
        // Normal Goto with a single successor: behavior unchanged.
        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            body: vec![],
            terminator: Terminator::Goto(BlockId(1)),
            preds: smallvec![],
            succs: smallvec![BlockId(1)],
        };
        let ssa = SsaBody {
            blocks: vec![block.clone()],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: std::collections::HashMap::new(),
            exception_edges: vec![],
        };
        let cfg: Cfg = Graph::new();
        let interner = SymbolInterner::new();
        let local_summaries: FuncSummaries = std::collections::HashMap::new();
        let transfer = SsaTaintTransfer {
            lang: Lang::JavaScript,
            namespace: "",
            interner: &interner,
            local_summaries: &local_summaries,
            global_summaries: None,
            interop_edges: &[],
            global_seed: None,
            const_values: None,
            type_facts: None,
            ssa_summaries: None,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases: None,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
        };
        let exit_state = SsaTaintState::initial();

        let succ_states = compute_succ_states(&block, &cfg, &ssa, &transfer, &exit_state);
        assert_eq!(succ_states.len(), 1);
        assert_eq!(succ_states[0].0, BlockId(1));
    }
}
