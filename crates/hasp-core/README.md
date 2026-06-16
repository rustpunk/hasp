# hasp-core

Core contracts, errors, and traits for [`hasp`](https://crates.io/crates/hasp)
— the URL-addressed secrets library. Part of the rustpunk portfolio.

This crate defines the `Backend` trait that every `hasp` backend implements,
the concrete `Error` type, the `SecretString` redaction boundary, the
`hardening` process-protection module, and shared types (`Entry`,
`ProxyConfig`, `RetryBackend`) used across the workspace. Most users should
depend on [`hasp`](https://crates.io/crates/hasp) directly rather than on this
crate.

## License

Licensed under either of [MIT](https://opensource.org/license/mit) or
[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) at your option.
