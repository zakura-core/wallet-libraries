// Included by a module that defines `api`, naming one implementation's items
// under the paths below. Everything here is deterministic: the same inputs give
// the same bytes on every run of the same implementation.

/// Every frozen output, by name: hex for short encodings, `sha256:len` for long ones.
pub fn vectors(work: &std::path::Path) -> std::collections::BTreeMap<String, String> {
    #[allow(unused_imports)]
    use api::traits::*;
    use api::events::{FeeState, ReceiveEvent, SpendEvent, TransactionMetadata, TransparentEvent, Txid};
    use api::filter::{BlockHash, ScriptBytes, ShardKey};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    let mut out = BTreeMap::new();
    let mut put = |name: String, value: String| {
        assert!(out.insert(name.clone(), value).is_none(), "{name} twice");
    };
    let long = |bytes: &[u8]| format!("sha256:{}:{}", hex::encode(Sha256::digest(bytes)), bytes.len());
    let hash = |seed: u8| BlockHash::from_internal_bytes([seed; 32]);
    let txid = |seed: u8| Txid([seed; 32]);

    // Events, with and without metadata.
    let receive = ReceiveEvent {
        metadata: None,
        height: 3_428_400,
        txid: txid(1),
        transaction_index: 3,
        output_index: 1,
        value: 123_456,
        coinbase: false,
    };
    let spend = SpendEvent {
        metadata: Some(TransactionMetadata {
            fee: FeeState::Exact(10_000),
            transparent_input_count: 2,
            has_shielded_components: true,
        }),
        height: 3_428_401,
        spending_txid: txid(2),
        transaction_index: 7,
        input_index: 1,
        spent_txid: txid(1),
        spent_output_index: 1,
    };
    let coinbase = ReceiveEvent {
        metadata: Some(TransactionMetadata {
            fee: FeeState::NotApplicable,
            transparent_input_count: 0,
            has_shielded_components: false,
        }),
        height: 3_428_402,
        txid: txid(3),
        transaction_index: 0,
        output_index: 0,
        value: 312_500_000,
        coinbase: true,
    };
    let unknown_fee = ReceiveEvent {
        metadata: Some(TransactionMetadata {
            fee: FeeState::Unknown,
            transparent_input_count: 300,
            has_shielded_components: false,
        }),
        ..receive
    };
    let events = [
        ("receive", TransparentEvent::Receive(receive)),
        ("spend", TransparentEvent::Spend(spend)),
        ("coinbase", TransparentEvent::Receive(coinbase)),
        ("unknown-fee", TransparentEvent::Receive(unknown_fee)),
    ];
    for (name, event) in events {
        put(format!("events/{name}"), hex::encode(event.to_bytes().unwrap()));
    }
    put(
        "events/receive/legacy".into(),
        hex::encode(TransparentEvent::Receive(receive).to_legacy_bytes()),
    );

    // Filters: per-block and range, their envelopes, and the digest chain.
    let scripts: Vec<ScriptBytes> = (0..24u8)
        .map(|n| {
            let mut script = vec![0x76, 0xa9, 20];
            script.extend([n; 20]);
            script.extend([0x88, 0xac]);
            ScriptBytes::new(script)
        })
        .chain([
            ScriptBytes::new(vec![0xa9, 20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0x87]),
            ScriptBytes::new(vec![0x6a, 4, 1, 2, 3, 4]),
            ScriptBytes::new(vec![]),
        ])
        .collect();
    let genesis = BlockHash::from_display_hex(api::filter::MAINNET_GENESIS_DISPLAY).unwrap();
    let block = api::filter_build::build_filter(hash(9), &scripts).unwrap();
    put("filter/block".into(), hex::encode(block.as_slice()));
    let mut header = api::filter::GENESIS_PREDECESSOR;
    for (name, profile) in [
        ("v1", &api::filter::RANGE_PROFILE_V1),
        ("v2", &api::filter::RANGE_PROFILE_V2),
    ] {
        let key = ShardKey::derive(profile.name, genesis, 4, 3_428_143, 3_428_342, hash(4));
        let filter = api::filter_build::build_range_filter_for(profile, key, &scripts).unwrap();
        put(format!("filter/range/{name}"), hex::encode(filter.as_slice()));
        let digest = api::filter::filter_hash(filter.as_slice());
        header = api::filter::filter_header(digest, header);
        put(format!("filter/range/{name}/hash"), digest.to_display_hex());
        put(format!("filter/range/{name}/header"), header.to_display_hex());
        let batch = api::filter::RangeFilterBatch {
            version: api::filter::RANGE_ENVELOPE_VERSION,
            genesis,
            profile: profile.name.into(),
            start_shard: 4,
            records: vec![api::filter::RangeFilterRecord {
                shard_id: 4,
                start_height: 3_428_143,
                end_height: 3_428_342,
                parent_block_hash: hash(3),
                terminal_block_hash: hash(4),
                filter: filter.as_slice().to_vec(),
            }],
        };
        put(format!("filter/range/{name}/envelope"), long(&batch.encode()));
    }
    let batch = api::filter::FilterBatch {
        version: api::filter::ENVELOPE_VERSION,
        genesis,
        profile: api::filter::PROFILE.into(),
        start_height: 3_428_143,
        stop_block_hash: hash(9),
        records: vec![api::filter::FilterRecord {
            height: 3_428_143,
            block_hash: hash(9),
            filter: block.as_slice().to_vec(),
        }],
    };
    put("filter/block/envelope".into(), hex::encode(batch.encode()));

    // Placement, tags and page rows.
    let terminal = hash(7);
    for shard_id in [0u64, 7, 1_234] {
        for rows in [2_048u64, 32_768] {
            for (n, script) in scripts.iter().take(6).enumerate() {
                put(
                    format!("shard/candidate-rows/{shard_id}/{rows}/{n}"),
                    format!("{:?}", api::shard::candidate_rows(shard_id, script.as_slice(), rows)),
                );
            }
        }
        for counter in [0u32, 1] {
            let salt = api::shard::tag::tag_salt(shard_id, &terminal, counter);
            put(format!("shard/tag-salt/{shard_id}/{counter}"), hex::encode(salt));
            put(
                format!("shard/script-tag/{shard_id}/{counter}"),
                hex::encode(api::shard::tag::script_tag(&salt, scripts[0].as_slice())),
            );
            put(
                format!("shard/page-tag-salt/{shard_id}/{counter}"),
                hex::encode(api::shard::tag::page_tag_salt(shard_id, 3, 3_428_300, &terminal, counter)),
            );
        }
    }
    let page = api::shard::page_row::encode_page_row(&[
        api::shard::page_row::PageEntry::new(
            [5; 14],
            0,
            1,
            vec![
                TransparentEvent::Receive(receive),
                TransparentEvent::Spend(spend),
            ],
        )
        .unwrap(),
        api::shard::page_row::PageEntry::new([6; 14], 2, 3, vec![TransparentEvent::Receive(coinbase)]).unwrap(),
    ])
    .unwrap();
    put("shard/page-row".into(), long(&page));

    // Native profiles: every table of every geometry, history and display.
    let mut tables: Vec<(&str, String, String, u64, u32)> = Vec::new();
    for geometry in api::shard::layout::PROFILES {
        tables.push((api::shard::manifest::SCHEMA, geometry.name.into(), "directory".into(), geometry.directory_rows, geometry.directory_row_bytes as u32));
        for child in [0u32, 1, 31] {
            tables.push((api::shard::manifest::SCHEMA, geometry.name.into(), api::shard::manifest::pages_table(child), geometry.page_rows, geometry.page_row_bytes as u32));
        }
    }
    for geometry in api::shard::display::DISPLAY_PROFILES {
        let kind = api::shard::display::DisplayKind::TxDirectory;
        tables.push((api::shard::display::NATIVE_SCHEMA, geometry.name.into(), kind.as_str().into(), kind.rows(geometry), kind.row_bytes(geometry)));
        put(
            format!("display/setup-seed/{}", geometry.name),
            api::shard::display::setup_seed(geometry, kind).to_string(),
        );
    }
    for (schema, geometry, table, rows, row_bytes) in &tables {
        let name = format!("native/{schema}/{geometry}/{table}");
        let profile = api::native::TableProfile::new(schema, geometry, table, *rows, *row_bytes).unwrap();
        put(format!("{name}/scheme"), serde_json::to_string(&profile.scheme).unwrap());
        put(format!("{name}/scheme/digest"), profile.scheme.digest());
        put(
            format!("{name}/dithered-scheme"),
            serde_json::to_string(&profile.dithered_scheme).unwrap(),
        );
        let seeds = api::native::table_seeds(schema, geometry, table);
        put(format!("{name}/seeds"), format!("{}/{}", hex::encode(seeds.query_masks), hex::encode(seeds.packing)));
    }

    // Native framing: a seeded query to a directory (16-bit) and a page
    // (8-bit) table, the fixture's answer and the decoded row.
    let geometry = &api::shard::layout::PROFILES[0];
    for (table, rows, row_bytes) in [
        ("directory", geometry.directory_rows, geometry.directory_row_bytes),
        ("pages-0", geometry.page_rows, geometry.page_row_bytes),
    ] {
        use rand_chacha::rand_core::SeedableRng as _;
        let profile = std::sync::Arc::new(
            api::native::TableProfile::new(api::shard::manifest::SCHEMA, geometry.name, table, rows, row_bytes as u32).unwrap(),
        );
        let content: Vec<u8> = (0..profile.rows * profile.row_bytes / 64)
            .map(|i| (i * 31 % 251) as u8)
            .collect();
        let segment = api::fixture::native::Segment::build(profile.clone(), &content).unwrap();
        let name = format!("native/framing/{table}");
        put(format!("{name}/public"), long(segment.public()));
        put(format!("{name}/epoch"), hex::encode(segment.epoch()));
        let target = 5;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([9; 32]);
        let (secret, query) = profile
            .native
            .prepare_dithered_with(&profile.setup, &profile.masks, profile.rows, target, &mut rng)
            .unwrap();
        put(format!("{name}/query"), long(&query));
        let binding = api::shard::manifest::query_binding(&"ab".repeat(32), table);
        let mut body = binding.to_vec();
        body.extend(&query);
        let (keys, selection) = api::fixture::native::parse(&profile, binding, &body, profile.rows).unwrap();
        let reply = segment.answer(binding, &keys, &selection).unwrap();
        put(format!("{name}/reply"), long(&reply));
        let row = profile.decode(&secret, segment.public(), &reply[16..]).unwrap();
        let expected: Vec<u8> = (0..profile.row_bytes)
            .map(|i| content.get(target * profile.row_bytes + i).copied().unwrap_or(0))
            .collect();
        assert_eq!(row, expected, "{table}: the decoded row is the row");
    }

    // The txid display publication: one recent shard.
    {
        use api::shard::display::{
            DISPLAY_SCHEMA, DisplayMap, DisplayMapEntry, DisplaySealParams, DisplayTable, ManifestHeader, TXID_4K8,
        };
        use api::shard::txid::{Address, AddressKind, DisplayEntry, EntryOutput, Tag};
        let entries: Vec<DisplayEntry> = (0..40u8)
            .map(|n| DisplayEntry {
                tag: Tag::of(&txid(n)),
                coinbase: n == 0,
                shielded_components: n % 3 == 0,
                multiple_source_scripts: n % 5 == 0 && n > 0 && n % 4 > 0,
                shielded_and_transparent_funding: n % 21 == 0 && n > 0,
                fee: if n == 0 { 0 } else { 1_000 + u64::from(n) },
                input_count: if n == 0 { 0 } else { 1 + u32::from(n % 4) },
                output_count: 1 + u32::from(n % 3),
                source: if n == 0 {
                    Address::ABSENT
                } else {
                    Address { kind: AddressKind::P2pkh, hash: [n; 20] }
                },
                outputs: [
                    Some(EntryOutput { value: 50_000 + u64::from(n), address: Address { kind: AddressKind::P2sh, hash: [n ^ 0xff; 20] } }),
                    (n % 3 > 0).then_some(EntryOutput { value: 7, address: Address::OTHER }),
                ],
            })
            .collect();
        let built = api::shard_build::display_build_shard(0, &TXID_4K8, 1, &entries).unwrap();
        for table in built.tables() {
            for (segment, rows) in built.segments(table).iter().enumerate() {
                put(format!("display/table/{}/{segment}", table.label()), long(rows));
            }
        }
        let manifest = api::shard::display::DisplayManifest::new(
            ManifestHeader {
                network: "main".into(),
                genesis_hash: "ee".repeat(32),
                shard_id: 0,
                start_height: 3_000_000,
                end_height: 3_000_099,
                parent_block_hash: "aa".repeat(32),
                terminal_block_hash: "bb".repeat(32),
                parent_manifest_digest: String::new(),
                sealed: false,
                revision: 0,
                supersedes: String::new(),
                archive_target: 1,
            },
            &TXID_4K8,
            &built,
        );
        manifest.validate().unwrap();
        let digest = manifest.digest();
        put("display/manifest".into(), long(&manifest.canonical_bytes()));
        put("display/manifest/digest".into(), digest.clone());
        put(
            "display/query-binding".into(),
            hex::encode(api::shard::display::query_binding(&digest, DisplayTable::Directory(0))),
        );
        let map = DisplayMap {
            schema: DISPLAY_SCHEMA.into(),
            network: "main".into(),
            genesis_hash: "ee".repeat(32),
            seal: DisplaySealParams { n_archive: 1, n_recent: 1, archive_target: 1, recent_window: 1, reorg_margin: 1 },
            start_height: 3_000_000,
            first_shard_id: 0,
            shards: vec![DisplayMapEntry::from_manifest(&manifest, &digest)],
        };
        put("display/map".into(), long(&map.to_bytes()));
        put("display/map/sha256".into(), map.sha256());
        let split = map.split().unwrap();
        put("display/map/recent".into(), long(&split.recent_bytes));
    }

    // A history publication, its map, filters, manifests and tables as files,
    // and every table's published setup.
    {
        use api::fixture::service::{GEOMETRY, InProcess, SEAL, ShardSpec, WIDE, publish, synthetic};
        let script = |n: u32| {
            let mut bytes = vec![0x76, 0xa9, 20];
            bytes.extend(n.to_le_bytes());
            bytes.extend([0xcd; 16]);
            bytes.extend([0x88, 0xac]);
            ScriptBytes::new(bytes)
        };
        let ev = |height: u64, n: u32, index: u32| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&n.to_le_bytes());
            id[4..12].copy_from_slice(&height.to_le_bytes());
            TransparentEvent::Receive(ReceiveEvent {
                metadata: None,
                height: height as u32,
                txid: Txid(id),
                transaction_index: 1,
                output_index: index,
                value: 1_000 + u64::from(n),
                coinbase: false,
            })
        };
        let spent = |height: u64, n: u32, from: u64| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&n.to_le_bytes());
            id[4..12].copy_from_slice(&from.to_le_bytes());
            TransparentEvent::Spend(SpendEvent {
                metadata: None,
                height: height as u32,
                spending_txid: Txid([0x99; 32]),
                transaction_index: 2,
                input_index: 0,
                spent_txid: Txid(id),
                spent_output_index: 0,
            })
        };
        let h0 = 3_428_143u64;
        let range = |start: u64, end: u64, salt: u32| -> Vec<_> {
            (0..60u32)
                .map(|n| (script(salt * 1_000 + n), ev(start + u64::from(n) * 3 % (end - start + 1), salt * 1_000 + n, 0)))
                .collect()
        };
        // A long history for one script, pushed into page shards.
        let mut paged = range(h0 + 200, h0 + 399, 1);
        for k in 0..12u64 {
            paged.push((script(42), ev(h0 + 200 + k * 15, 42, k as u32)));
        }
        paged.push((script(42), spent(h0 + 390, 42, h0 + 200)));
        let mut first = range(h0, h0 + 199, 0);
        first.push((script(43), ev(h0 + 10, 43, 0)));
        let shards = vec![
            ShardSpec { malformed_entries: vec![script(43)], ..ShardSpec::first(h0, h0 + 199, true, first) },
            ShardSpec { page_span: 60, ..ShardSpec::first(h0 + 200, h0 + 399, true, paged) },
            ShardSpec { geometry: WIDE, ..ShardSpec::first(h0 + 400, h0 + 599, true, range(h0 + 400, h0 + 599, 2)) },
            ShardSpec {
                geometry: GEOMETRY,
                revision: 3,
                ..ShardSpec::first(h0 + 600, h0 + 649, false, range(h0 + 600, h0 + 649, 3))
            },
        ];
        let dir = work.join("publication");
        let map = publish(&dir, &shards, SEAL, synthetic, vec![]);
        let mut files = Vec::new();
        collect(&dir, &dir, &mut files);
        files.sort();
        for (path, bytes) in &files {
            put(format!("publication/{path}"), long(bytes));
        }
        let service = InProcess::serve(&dir);
        let get = |path: String| {
            let reply = service.answer(
                axum::http::Request::builder().method("GET").uri(path).body(Vec::new()).unwrap(),
            );
            (reply.status().as_u16(), reply.into_body())
        };
        for entry in &map.shards {
            let base = format!("/v2/shards/{}/revisions/{}", entry.shard_id, entry.manifest_digest);
            let mut tables = vec!["directory".to_string()];
            tables.extend((0..32).map(api::shard::manifest::pages_table));
            for table in tables {
                put(
                    format!("publication/query-binding/{}/{table}", entry.shard_id),
                    hex::encode(api::shard::manifest::query_binding(&entry.manifest_digest, &table)),
                );
                for segment in 0.. {
                    let (status, body) = get(format!("{base}/setup/{table}/{segment}"));
                    if status != 200 {
                        break;
                    }
                    put(format!("publication/setup/{}/{table}/{segment}", entry.shard_id), long(&body));
                }
            }
            let (status, body) = get(format!("{base}/manifest"));
            assert_eq!(status, 200);
            put(format!("publication/manifest/{}", entry.shard_id), long(&body));
        }
        for route in ["/v2/shards/init", "/v2/filters/shards"] {
            let (status, body) = get(route.into());
            put(format!("publication/route{route}"), format!("{status} {}", long(&body)));
        }
    }
    out
}

/// Every file under `dir`, by its path relative to `root`.
fn collect(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect(root, &path, out);
        } else {
            let name = path.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            out.push((name, std::fs::read(&path).unwrap()));
        }
    }
}
