//! Map bytes per lookup at the live window (13 archives and the recent shard)
//! and at genesis coverage (425 archives and the recent shard): what the
//! client fetches of the split map cold, warm and after a 409, raw and
//! gzipped, against the full map it no longer reads.
//!
//! The map is synthetic with the live map's entry shape. Every manifest
//! request is answered 503, so each lookup stops right after placement: the
//! transcript is the map traffic, plus init and that one manifest request,
//! which map bytes exclude.

use flate2::{write::GzEncoder, Compression};
use sha2::{Digest, Sha256};
use std::io::Write;
use transparent_native::NativeScheme;
use transparent_shard::display::{
    DisplayMap, DisplayMapEntry, DisplaySealParams, SplitMap, DISPLAY_SCHEMA, INDEX_CHUNK_SHARDS,
};
use transparent_txid_client::{
    Route, TransportError, TxidDisplayClient, TxidError, TxidReply, TxidRequest, TxidTransport,
};

/// The first display height of the live publication.
const START: u64 = 3_407_001;
/// About the live seal interval.
const BLOCKS: u64 = 7_600;

fn hex_of(tag: &str, n: u64) -> String {
    hex::encode(
        Sha256::new()
            .chain_update(tag)
            .chain_update(n.to_le_bytes())
            .finalize(),
    )
}

fn entry(shard_id: u64, sealed: bool) -> DisplayMapEntry {
    let start = START + shard_id * BLOCKS;
    let end = start + BLOCKS - 1;
    DisplayMapEntry {
        shard_id,
        start_height: start,
        end_height: end,
        parent_block_hash: hex_of("block", start - 1),
        terminal_block_hash: hex_of("block", end),
        geometry: "txid-2k8".into(),
        n_buckets: 1,
        directory_segments: vec![1],
        placement_seeds: vec![0],
        records: 40_000 + shard_id % 7_919,
        min_bucket_records: 40_000 + shard_id % 7_919,
        manifest_digest: hex_of("manifest", shard_id),
        revision: if sealed { 0 } else { 1_264 },
        sealed,
    }
}

fn full_map(archives: u64) -> DisplayMap {
    DisplayMap {
        schema: DISPLAY_SCHEMA.into(),
        network: "main".into(),
        genesis_hash: "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08".into(),
        seal: DisplaySealParams {
            n_archive: 1,
            n_recent: 1,
            archive_target: 40_000,
            recent_window: 10_000,
            reorg_margin: 100,
        },
        start_height: START,
        first_shard_id: 0,
        shards: (0..=archives).map(|id| entry(id, id < archives)).collect(),
    }
}

fn gzip(bytes: &[u8]) -> usize {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(6));
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap().len()
}

/// Init listing `txid-2k`. Its parameters are placeholders: no lookup gets
/// as far as comparing them.
fn init() -> Vec<u8> {
    let scheme = NativeScheme {
        profile: String::new(),
        d: 0,
        q_bits: 0,
        p_bits: 0,
        gadget_bits: 0,
        ell: 0,
        secret: String::new(),
        mask_bits: 0,
        query_bits: 0,
        response_bits: 0,
        rows: 0,
        row_bytes: 0,
        cols: 0,
        native_encoding: String::new(),
        query_mask_seed: String::new(),
        packing_setup_id: String::new(),
        request_bytes: 0,
        public_bytes: 0,
        response_bytes: 0,
    };
    serde_json::json!({
        "schema": DISPLAY_SCHEMA,
        "codec": transparent_shard::txid::CODEC,
        "bucket_domain": std::str::from_utf8(transparent_shard::display::BUCKET_DOMAIN).unwrap(),
        "native_schema": transparent_shard::display::NATIVE_SCHEMA,
        "geometries": [{
            "name": "txid-2k8",
            "txdirectory": {"rows": 0, "row_bytes": 0, "scheme": scheme, "setup_seed": 0},
        }],
    })
    .to_string()
    .into_bytes()
}

/// Serves init, the recent map and chunks of one split, logging each reply's
/// raw and gzipped body length, and answers every manifest request 503.
struct Server {
    split: SplitMap,
    log: Vec<(Route, usize, usize)>,
}

impl TxidTransport for Server {
    fn send(&mut self, request: TxidRequest) -> Result<TxidReply, TransportError> {
        let mut status = 200;
        let (body, map_sha256) = match request.route {
            Route::Init => (init(), None),
            Route::Map => (
                self.split.recent_bytes.clone(),
                Some(self.split.recent_sha256.clone()),
            ),
            Route::MapChunk => {
                let digest = request.path().rsplit('/').next().unwrap();
                let chunk = self
                    .split
                    .chunks
                    .iter()
                    .find(|chunk| chunk.sha256 == digest)
                    .expect("a chunk the map names");
                (chunk.bytes.clone(), None)
            }
            Route::Manifest => {
                status = 503;
                (Vec::new(), None)
            }
            route => panic!("{route:?} is past placement"),
        };
        self.log.push((request.route, body.len(), gzip(&body)));
        Ok(TxidReply {
            status,
            retry_after: None,
            map_sha256,
            body,
        })
    }
}

/// Raw and gzipped map bytes of a transcript: the map and chunk routes.
fn map_bytes(log: &[(Route, usize, usize)]) -> (usize, usize) {
    log.iter()
        .filter(|(route, _, _)| matches!(route, Route::Map | Route::MapChunk))
        .fold((0, 0), |(raw, gz), (_, r, g)| (raw + r, gz + g))
}

fn routes(log: &[(Route, usize, usize)]) -> Vec<Route> {
    log.iter().map(|(route, _, _)| *route).collect()
}

struct Measured {
    full: (usize, usize),
    cold_archive: (usize, usize),
    cold_recent: (usize, usize),
    warm: (usize, usize),
    after_409: (usize, usize),
    chunk: (usize, usize),
}

fn measure(archives: u64) -> Measured {
    let full = full_map(archives);
    let full_bytes = full.to_bytes();
    let mut server = Server {
        split: full.split().unwrap(),
        log: Vec::new(),
    };
    let never = || false;
    let stopped = |client: &mut TxidDisplayClient, server: &mut Server, height: u64| {
        assert_eq!(
            client.lookup(server, [7; 32], height, &never),
            Err(TxidError::Unavailable { retry_after: None })
        );
        std::mem::take(&mut server.log)
    };
    let oldest = START + 10;

    // Cold, at the oldest archive: init, the recent map, the oldest chunk.
    let mut client = TxidDisplayClient::new();
    let log = stopped(&mut client, &mut server, oldest);
    assert_eq!(
        routes(&log),
        [Route::Init, Route::Map, Route::MapChunk, Route::Manifest]
    );
    assert!(log[2].1 <= server.split.chunks[0].bytes.len());
    let cold_archive = map_bytes(&log);
    let chunk = (log[2].1, log[2].2);

    // Warm: another height of the same chunk sends no map request.
    let log = stopped(&mut client, &mut server, oldest + BLOCKS * 3);
    assert_eq!(routes(&log), [Route::Manifest]);
    let warm = map_bytes(&log);

    // A block moves the recent revision; a 409 refetches the recent map and
    // no chunk, because the chunk is cached by digest.
    let mut next = full.clone();
    let recent = next.shards.last_mut().unwrap();
    recent.end_height += 1;
    recent.revision += 1;
    recent.manifest_digest = hex_of("manifest-next", archives);
    server.split = next.split().unwrap();
    client.invalidate_map();
    let log = stopped(&mut client, &mut server, oldest);
    assert_eq!(routes(&log), [Route::Map, Route::Manifest]);
    let after_409 = map_bytes(&log);

    // Cold, at the recent shard: no chunk at all.
    let mut client = TxidDisplayClient::new();
    let tip = START + archives * BLOCKS + 5;
    let log = stopped(&mut client, &mut server, tip);
    assert_eq!(routes(&log), [Route::Init, Route::Map, Route::Manifest]);
    let cold_recent = map_bytes(&log);

    Measured {
        full: (full_bytes.len(), gzip(&full_bytes)),
        cold_archive,
        cold_recent,
        warm,
        after_409,
        chunk,
    }
}

#[test]
fn split_map_bytes_at_the_live_window_and_at_genesis() {
    for (archives, chunks) in [(13u64, 1usize), (425, 14)] {
        let m = measure(archives);
        eprintln!(
            "map bytes at {} entries ({archives} archives, {chunks} chunks), raw / gzip: \
             full map {} / {}; cold archive lookup {} / {}; cold recent lookup {} / {}; \
             warm {} / {}; after a 409 {} / {}; one chunk {} / {}",
            archives + 1,
            m.full.0,
            m.full.1,
            m.cold_archive.0,
            m.cold_archive.1,
            m.cold_recent.0,
            m.cold_recent.1,
            m.warm.0,
            m.warm.1,
            m.after_409.0,
            m.after_409.1,
            m.chunk.0,
            m.chunk.1,
        );
        assert_eq!(full_map(archives).split().unwrap().chunks.len(), chunks);
        assert_eq!(m.warm, (0, 0));
        // The recent map: about 1 KB of fixed fields and the recent entry,
        // plus about 100 B raw per chunk reference.
        let recent_raw = 1_100 + 110 * chunks;
        assert!(m.after_409.0 <= recent_raw, "{}", m.after_409.0);
        assert!(m.cold_recent.0 <= recent_raw);
        // A full chunk is 32 entries of about 610 B raw, 5 KB gzipped.
        assert!(m.chunk.0 <= 620 * INDEX_CHUNK_SHARDS as usize);
        assert!(m.chunk.1 <= 6_000);
        assert!(m.cold_archive.1 <= m.after_409.1 + 6_000);
        if archives == 425 {
            // Under 7.5 KB cold and about 1 KB after a 409, against about
            // 248 KB raw and 46 KB gzipped for the full map.
            assert!(m.cold_archive.1 <= 7_500, "{}", m.cold_archive.1);
            assert!(m.after_409.1 <= 1_200, "{}", m.after_409.1);
            assert!(m.full.0 >= 240_000 && m.full.1 >= 40_000);
        }
    }
}
