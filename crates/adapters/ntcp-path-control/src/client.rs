//! Blocking client of the control socket (used by `ntcp-pathctl`).

use crate::protocol::{
    self, ClientEntry, LENGTH_PREFIX, MAX_RESPONSE_BODY, PathEntry, Payload, Request, Response,
    RouteEntry, Status,
};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// The client waits as long as the server allows a reply to drain.
const TIMEOUT: Duration = Duration::from_secs(crate::server::FRAME_SECONDS + 1);

pub struct Client {
    stream: UnixStream,
}

#[derive(Debug)]
pub enum ClientError {
    Io(io::Error),
    /// The reply could not be decoded.
    Protocol,
    /// The server answered with a non-Ok status (nothing changed).
    Status(Status),
}

impl From<io::Error> for ClientError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl Client {
    pub fn connect(path: &Path) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        Ok(Self { stream })
    }

    /// Send one request and read its reply. A server that refuses the
    /// connection at accept (`Unauthorized`, `Busy`) replies and closes
    /// before reading anything, so the write may fail with a broken pipe or
    /// reset; the reply already delivered to this socket is then read and
    /// returned, and the write error only when no complete frame arrived.
    pub fn call(&mut self, request: &Request) -> Result<Response, ClientError> {
        match self.stream.write_all(&protocol::encode_request(request)) {
            Ok(()) => self.read_response(),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                ) =>
            {
                match self.read_response() {
                    Err(ClientError::Io(_)) => Err(ClientError::Io(error)),
                    other => other,
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Read one reply frame.
    pub fn read_response(&mut self) -> Result<Response, ClientError> {
        let mut prefix = [0u8; LENGTH_PREFIX];
        self.stream.read_exact(&mut prefix)?;
        let len = u32::from_be_bytes(prefix) as usize;
        if len > MAX_RESPONSE_BODY {
            return Err(ClientError::Protocol);
        }
        let mut body = vec![0; len];
        self.stream.read_exact(&mut body)?;
        protocol::decode_response(&body).ok_or(ClientError::Protocol)
    }

    /// A call whose non-Ok status is an error.
    pub fn ok(&mut self, request: &Request) -> Result<Payload, ClientError> {
        let response = self.call(request)?;
        if response.status != Status::Ok {
            return Err(ClientError::Status(response.status));
        }
        Ok(response.payload)
    }

    /// Every route, read page by page under one listing revision.
    pub fn routes(&mut self) -> Result<Vec<RouteEntry>, ClientError> {
        self.pages(
            |cursor, revision| Request::QueryRoutes { cursor, revision },
            |payload| match payload {
                Payload::Routes(h, e) => Some((h, e)),
                _ => None,
            },
        )
    }

    pub fn paths(&mut self) -> Result<Vec<PathEntry>, ClientError> {
        self.pages(
            |cursor, revision| Request::QueryPaths { cursor, revision },
            |payload| match payload {
                Payload::Paths(h, e) => Some((h, e)),
                _ => None,
            },
        )
    }

    pub fn clients(&mut self, path: u64) -> Result<Vec<ClientEntry>, ClientError> {
        self.pages(
            |cursor, revision| Request::QueryClients {
                path,
                cursor,
                revision,
            },
            |payload| match payload {
                Payload::Clients(h, e) => Some((h, e)),
                _ => None,
            },
        )
    }

    fn pages<T>(
        &mut self,
        request: impl Fn(u32, u64) -> Request,
        split: impl Fn(Payload) -> Option<(protocol::PageHeader, Vec<T>)>,
    ) -> Result<Vec<T>, ClientError> {
        let mut all = Vec::new();
        let mut revision = 0;
        loop {
            let cursor = u32::try_from(all.len()).map_err(|_| ClientError::Protocol)?;
            let (header, entries) =
                split(self.ok(&request(cursor, revision))?).ok_or(ClientError::Protocol)?;
            if header.cursor != cursor || (cursor != 0 && header.revision != revision) {
                return Err(ClientError::Protocol);
            }
            revision = header.revision;
            let done = entries.is_empty();
            all.extend(entries);
            if done || all.len() >= header.total as usize {
                return Ok(all);
            }
        }
    }
}
