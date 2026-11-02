//! Body limits must stop reading before a peer finishes its response.

use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::mpsc,
    thread,
    time::Duration,
};

use zakura_pir_client::transparent::{HttpExchange, HttpFailure, HttpMethod, HttpRequest};

pub(super) fn assert_bounded_responses<E: HttpExchange>(make: impl Fn(String) -> E) {
    const SUCCESS_LIMIT: usize = 8;
    const ERROR_LIMIT: usize = 4;
    for (status, error_limit) in [(200, ERROR_LIMIT), (500, ERROR_LIMIT), (500, 0)] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (release, wait) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                headers.push(byte[0]);
                assert!(headers.len() < 4096);
            }
            // Leave the declared body unfinished. Collecting to EOF before
            // enforcing the limit would time out instead of returning it.
            write!(
                socket,
                "HTTP/1.1 {status} Test\r\nContent-Length: 1000000\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            let _ = socket.write_all(&[b'x'; SUCCESS_LIMIT + 1]);
            let _ = wait.recv_timeout(Duration::from_secs(5));
        });
        let result = make(origin).send(&HttpRequest {
            method: HttpMethod::Get,
            path: "/bounded".into(),
            template: "/bounded".into(),
            body: vec![],
            limit: SUCCESS_LIMIT,
            error_limit,
        });
        let _ = release.send(());
        worker.join().unwrap();
        if status == 200 {
            assert_eq!(result, Err(HttpFailure::TooLarge));
        } else {
            let reply = result.unwrap();
            assert_eq!(reply.status, status);
            assert_eq!(reply.body, vec![b'x'; error_limit]);
        }
    }
}
