//! Build as a separate test crate against the pinned wallet-pir checkout.
//! Queries traverse the real coordinator and two worker HTTP listeners.
use enhance_pir_server::{
    store::RecordJournal,
    types::{DatabaseId, ENHANCE_LAYOUT},
    v4::{
        control::{Group, Ledger, Replica},
        coordinator::Coordinator,
        worker::Worker,
    },
};
use futures_util::StreamExt;
use zakura_pir_enhance::{
    transport::{Client, Method, PendingClient, Request, ResponseBody, Transport},
    AcceptedAnchor, ClientError, ClientResourceLimits, EnhanceRecord, GenerationAcceptance,
    RECORD_BYTES,
};

struct LoopbackTransport(reqwest::Client);

impl LoopbackTransport {
    fn new() -> Self {
        Self(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        )
    }
}

impl Transport for LoopbackTransport {
    async fn execute(&self, request: Request) -> Result<ResponseBody, ClientError> {
        let mut body = request.response_body();
        let method = match request.method {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
        };
        let mut response = self
            .0
            .request(method, request.url)
            .body(request.body)
            .send()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        if !response.status().is_success() {
            return Err(ClientError::HttpStatus(response.status().as_u16()));
        }
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?
        {
            body.extend(&chunk)?;
        }
        Ok(body.finish())
    }
}

async fn query_position(
    client: &mut Client,
    transport: &LoopbackTransport,
    position: u64,
) -> Result<EnhanceRecord, ClientError> {
    let stream = client.query_batch(transport, [position])?;
    futures_util::pin_mut!(stream);
    stream.next().await.expect("one result").record
}

async fn serve(router: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, task)
}

fn record(position: u64) -> Vec<u8> {
    let mut bytes = vec![0; RECORD_BYTES];
    bytes[..8].copy_from_slice(&position.to_le_bytes());
    bytes
}

fn acceptance(height: u64, hash: u8, records: u64) -> GenerationAcceptance {
    GenerationAcceptance::new(
        "main",
        3_428_143,
        AcceptedAnchor::new(height, [hash; 32], records),
        ClientResourceLimits::with_cache(4_096, 1),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_client_round_trips_real_v4_http_and_requires_fresh_acceptance() {
    let root = tempfile::tempdir().unwrap();
    let mut tasks = Vec::new();
    let mut replicas = Vec::new();
    for index in 0..2 {
        let worker = Worker::open(&root.path().join(format!("worker-{index}"))).unwrap();
        let (url, task) = serve(worker.router()).await;
        tasks.push(task);
        replicas.push(Replica {
            name: format!("replica-{index}"),
            url,
            incarnation: String::new(),
            ledger: Ledger::default(),
        });
    }
    let coordinator = Coordinator::open(
        &root.path().join("control"),
        vec![Group {
            id: "group-1".into(),
            sequence: 0,
            replicas,
            settling: false,
        }],
    )
    .unwrap();
    let (origin, task) = serve(coordinator.clone().router()).await;
    tasks.push(task);
    let mut journal = RecordJournal::open(
        root.path().join("journal"),
        DatabaseId::Enhance,
        ENHANCE_LAYOUT,
    )
    .unwrap();
    journal
        .append_block(
            3_428_143,
            "01".repeat(32),
            &(0..67).map(record).collect::<Vec<_>>(),
        )
        .unwrap();
    coordinator
        .publish(&journal, 3_428_143, "01".repeat(32))
        .await
        .unwrap();

    let transport = LoopbackTransport::new();
    let pending = PendingClient::fetch(&transport, &origin).await.unwrap();
    assert_eq!(pending.manifest().coverage.records, 67);
    assert!(pending.accept(&acceptance(3_428_143, 2, 67)).is_err());
    let mut client = PendingClient::fetch(&transport, &origin)
        .await
        .unwrap()
        .accept(&acceptance(3_428_143, 1, 67))
        .unwrap();
    for position in [0, 32, 33, 65, 66, 33] {
        let answer = query_position(&mut client, &transport, position).await.unwrap();
        assert_eq!(
            answer.as_bytes(),
            record(position).as_slice(),
            "position {position}"
        );
    }
    assert!(query_position(&mut client, &transport, 67).await.is_err());

    // The sixth publication expires the first generation. A newly fetched
    // manifest still needs a new locally scanned anchor before its setup is used.
    for offset in 1..=5u64 {
        let position = journal.tree_size();
        let height = 3_428_143 + offset;
        let hash = format!("{offset:02x}").repeat(32);
        journal
            .append_block(height, hash.clone(), &[record(position)])
            .unwrap();
        coordinator.publish(&journal, height, hash).await.unwrap();
    }
    let stale = query_position(&mut client, &transport, 0).await.unwrap_err();
    assert_eq!(stale.http_status(), Some(410));
    let pending = PendingClient::fetch(&transport, &origin).await.unwrap();
    assert!(pending.accept(&acceptance(3_428_143, 1, 67)).is_err());
    let mut refreshed = PendingClient::fetch(&transport, &origin)
        .await
        .unwrap()
        .accept(&acceptance(3_428_148, 5, 72))
        .unwrap();
    assert_eq!(
        query_position(&mut refreshed, &transport, 71)
            .await
            .unwrap()
            .as_bytes(),
        record(71).as_slice()
    );
    for task in tasks {
        task.abort();
    }
}

/// Large release-only test: each step changes the server's shard query domain.
/// It also reaches the last populated row of a full 32K shard. The wallet
/// retrieves byte-exact records over the real coordinator and worker routes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "full 32K shard; run in release mode with ample local RAM and disk"]
async fn wallet_client_queries_every_v4_domain_over_real_http() {
    let root = tempfile::tempdir().unwrap();
    let mut tasks = Vec::new();
    let mut replicas = Vec::new();
    for index in 0..2 {
        let worker = Worker::open(&root.path().join(format!("worker-{index}"))).unwrap();
        let (url, task) = serve(worker.router()).await;
        tasks.push(task);
        replicas.push(Replica {
            name: format!("replica-{index}"),
            url,
            incarnation: String::new(),
            ledger: Ledger::default(),
        });
    }
    let coordinator = Coordinator::open(
        &root.path().join("control"),
        vec![Group {
            id: "group-1".into(),
            sequence: 0,
            replicas,
            settling: false,
        }],
    )
    .unwrap();
    let (origin, task) = serve(coordinator.clone().router()).await;
    tasks.push(task);
    let mut journal = RecordJournal::open(
        root.path().join("journal"),
        DatabaseId::Enhance,
        ENHANCE_LAYOUT,
    )
    .unwrap();
    let mut height = 3_428_142u64;
    let mut hash_byte = 0u8;
    let transport = LoopbackTransport::new();
    let span = 32_768 * 33u64;
    let loan_records = 4_096 * 33u64;
    let borrowed_position = (32_768 - 4_096) * 33u64;
    let mut before_loan: Option<Client> = None;
    let mut during_loan: Option<Client> = None;
    for (target_records, expected_rows) in [
        (1, 4_096),
        (4_096 * 33 + 1, 8_192),
        (8_192 * 33 + 1, 16_384),
        (16_384 * 33 + 1, 32_768),
        (32_768 * 33 - 1, 32_768),
        (32_768 * 33, 32_768),
        (32_768 * 33 + 4_096 * 33 - 1, 32_768),
        (32_768 * 33 + 4_096 * 33, 32_768),
    ] {
        while journal.tree_size() < target_records {
            let start = journal.tree_size();
            let end = (start + 8_192).min(target_records);
            let records: Vec<_> = (start..end).map(record).collect();
            height += 1;
            hash_byte = hash_byte.wrapping_add(1);
            journal
                .append_block(height, format!("{hash_byte:02x}").repeat(32), &records)
                .unwrap();
        }
        coordinator
            .publish(&journal, height, format!("{hash_byte:02x}").repeat(32))
            .await
            .unwrap();
        let accepted = GenerationAcceptance::new(
            "main",
            3_428_143,
            AcceptedAnchor::new(height, [hash_byte; 32], target_records),
            ClientResourceLimits::with_cache(32_768, 1),
        );
        let mut client = PendingClient::fetch(&transport, &origin)
            .await
            .unwrap()
            .accept(&accepted)
            .unwrap();
        assert_eq!(
            client.manifest().coverage.shards[0].logical_rows,
            expected_rows
        );
        for position in [0, 32, 33, target_records / 2, target_records - 1] {
            if position >= target_records {
                continue;
            }
            let answer = query_position(&mut client, &transport, position).await.unwrap();
            assert_eq!(
                answer.as_bytes(),
                record(position).as_slice(),
                "position {position}, rows {expected_rows}"
            );
        }
        assert!(query_position(&mut client, &transport, target_records)
            .await
            .is_err());
        if target_records == span - 1 {
            before_loan = Some(client);
        } else if target_records == span {
            assert_eq!(
                client
                    .manifest()
                    .coverage
                    .locate(borrowed_position)
                    .unwrap()
                    .0
                    .id,
                1
            );
            let old = before_loan.as_mut().unwrap();
            assert_eq!(
                query_position(old, &transport, borrowed_position)
                    .await
                    .unwrap()
                    .as_bytes(),
                record(borrowed_position).as_slice()
            );
            during_loan = Some(client);
        } else if target_records == span + loan_records {
            assert!(client.manifest().coverage.loan.is_none());
            assert_eq!(
                client
                    .manifest()
                    .coverage
                    .locate(borrowed_position)
                    .unwrap()
                    .0
                    .id,
                0
            );
            let old_borrower = during_loan.as_mut().unwrap();
            assert_eq!(
                query_position(old_borrower, &transport, borrowed_position)
                    .await
                    .unwrap()
                    .as_bytes(),
                record(borrowed_position).as_slice()
            );
        }
    }
    for task in tasks {
        task.abort();
    }
}
