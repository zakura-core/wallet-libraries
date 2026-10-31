//! Local malformed-input and output-failure checks.
use std::io::{self, Read, Write};
use zakura_filters::{BitStreamReader, GcsFilterWriter, read_compact_size, write_compact_size};

struct InterruptedReader<'a> {
    bytes: &'a [u8],
    interrupt: bool,
}

impl Read for InterruptedReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.interrupt = !self.interrupt;
        if self.interrupt {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let len = self.bytes.len().min(output.len()).min(1);
        output[..len].copy_from_slice(&self.bytes[..len]);
        self.bytes = &self.bytes[len..];
        Ok(len)
    }
}

struct InterruptedWriter {
    bytes: Vec<u8>,
    limit: usize,
    interrupt: bool,
}

impl Write for InterruptedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.interrupt = !self.interrupt;
        if self.interrupt {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.bytes.len() == self.limit {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let len = bytes.len().min(1);
        self.bytes.extend_from_slice(&bytes[..len]);
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn interrupted_short_reads_retry_and_truncation_consumes_the_prefix() {
    let mut reader = InterruptedReader {
        bytes: &[0xfe, 0, 0, 1, 0, 0x42],
        interrupt: false,
    };
    assert_eq!(read_compact_size(&mut reader).unwrap(), 65536);
    assert_eq!(reader.bytes, [0x42]);
    let mut input = &[0xff, 1, 2, 3, 4][..];
    assert_eq!(
        read_compact_size(&mut input).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert!(input.is_empty());

    let mut reader = InterruptedReader {
        bytes: &[0xab],
        interrupt: false,
    };
    let mut bits = BitStreamReader::new(&mut reader);
    assert_eq!(bits.read(4).unwrap(), 0xa);
    assert_eq!(bits.read(4).unwrap(), 0xb);
    assert_eq!(
        bits.read(1).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[test]
fn interrupted_short_writes_retry_and_failures_preserve_the_written_prefix() {
    let mut writer = InterruptedWriter {
        bytes: Vec::new(),
        limit: usize::MAX,
        interrupt: false,
    };
    assert_eq!(write_compact_size(&mut writer, u64::MAX).unwrap(), 9);
    assert_eq!(writer.bytes, [0xff; 9]);

    let mut writer = InterruptedWriter {
        limit: 3,
        bytes: Vec::new(),
        interrupt: false,
    };
    assert_eq!(
        write_compact_size(&mut writer, u64::from(u32::MAX))
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(writer.bytes, [0xfe, 0xff, 0xff]);

    let mut writer = InterruptedWriter {
        limit: 1,
        bytes: Vec::new(),
        interrupt: false,
    };
    let mut filter = GcsFilterWriter::new(&mut writer, 0, 0, 1024, 10);
    filter.add_element(b"one");
    assert_eq!(
        filter.finish().unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(writer.bytes, [1]);
}

#[test]
fn zero_writes_retain_the_previous_unexpected_eof_error() {
    struct Zero;
    impl Write for Zero {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Ok(0)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        write_compact_size(&mut Zero, 1).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[test]
fn invalid_writer_parameters_fail_before_writing() {
    for (m, p) in [(0, 19), (1, 64), (u64::MAX, 19)] {
        let mut bytes = Vec::new();
        let mut writer = GcsFilterWriter::new(&mut bytes, 0, 0, m, p);
        writer.add_element(b"one");
        writer.add_element(b"two");
        assert_eq!(
            writer.finish().unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert!(bytes.is_empty());
    }
}

#[test]
fn writer_propagates_output_failure() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> Result<usize, std::io::Error> {
            Err(std::io::Error::from(std::io::ErrorKind::Other))
        }
        fn flush(&mut self) -> Result<(), std::io::Error> {
            Ok(())
        }
    }
    let mut output = Broken;
    let mut writer = GcsFilterWriter::new(&mut output, 0, 0, 1533, 10);
    writer.add_element(b"receiver");
    assert_eq!(
        writer.finish().unwrap_err().kind(),
        std::io::ErrorKind::Other
    );
    assert!(write_compact_size(&mut output, 65536).is_err());
}
