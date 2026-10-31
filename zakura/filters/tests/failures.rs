//! Local malformed-input and output-failure checks.
use zakura_filters::{GcsFilterWriter, write_compact_size};

#[test]
fn invalid_writer_parameters_fail_before_writing() {
    for (m, p) in [(0, 19), (1, 64), (u64::MAX, 19)] {
        let mut bytes = Vec::new();
        let mut writer = GcsFilterWriter::new(&mut bytes, 0, 0, m, p);
        writer.add_element(b"one");
        writer.add_element(b"two");
        assert_eq!(
            writer.finish().unwrap_err().kind(),
            bitcoin_io::ErrorKind::InvalidInput
        );
        assert!(bytes.is_empty());
    }
}

#[test]
fn writer_propagates_output_failure() {
    struct Broken;
    impl bitcoin_io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> Result<usize, bitcoin_io::Error> {
            Err(bitcoin_io::Error::from(bitcoin_io::ErrorKind::Other))
        }
        fn flush(&mut self) -> Result<(), bitcoin_io::Error> {
            Ok(())
        }
    }
    let mut output = Broken;
    let mut writer = GcsFilterWriter::new(&mut output, 0, 0, 1533, 10);
    writer.add_element(b"receiver");
    assert_eq!(
        writer.finish().unwrap_err().kind(),
        bitcoin_io::ErrorKind::Other
    );
    assert!(write_compact_size(&mut output, 65536).is_err());
}
