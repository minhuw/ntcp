# ntcp

**Normative TCP: a standards-first, event-driven TCP stack in Rust.**

## Status

Early development. Version 0.0.1 is a library scaffold only: **TCP is not
implemented, there is no usable networking API, and no RFC conformance is
claimed.** Do not use this release for networking or production workloads.

## Direction

- Track TCP requirements starting with RFC 9293 and document conformance through tests.
- Keep packet I/O, time, and scheduling under the caller's control.
- Support embedding in IX-style runtimes, DPDK applications, and other environments
  without making those integrations dependencies of the protocol core.
- Validate protocol behavior with deterministic tests and Linux interoperability tests.

These are goals, not features of this release. The library currently has no dependencies.

## Development

```sh
cargo test
cargo doc --no-deps
```

## License

MIT. See [LICENSE](LICENSE).
