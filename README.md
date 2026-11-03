# octet

TLS and cleartext HTTP/1.1 on one listening socket, chosen per connection by the first octet.

Course project for **Secure Communication Protocols and Architectures** (Сигурни протоколи и
архитектури за комуникации), MEng in Cybersecurity and Cybercrime Prevention, Technical
University of Sofia. The project document, in Bulgarian, is
[`docs/build/Main.pdf`](docs/build/Main.pdf).

## How it works

A TLS client always speaks first, and its first record carries the ClientHello, so the first
octet of every TLS connection is the record ContentType `handshake`, 0x16 (RFC 8446 section
5.1). Every HTTP method token is upper-case ASCII (RFC 9110 section 9.1), and so is the HTTP/2
preface. 0x16 is not a letter, so one octet separates the two.

For each accepted connection the server:

1. reads whatever has arrived, up to 2048 octets, under a deadline that started at accept;
2. classifies by the first octet: 0x16 is TLS, `A` to `Z` is HTTP, anything else is closed
   without a reply;
3. for TLS, hands the octets it already read to OpenSSL through a memory BIO, so the handshake
   sees the stream intact, and runs the handshake under the same deadline;
4. reads one HTTP/1.1 request, answers, and closes.

TLS settings: minimum version 1.2 (1.3 selectable), renegotiation and compression disabled,
strict ALPN (a client whose ALPN list lacks `http/1.1` gets the fatal `no_application_protocol`
alert), key checked against the certificate at start-up.

## Layout

| Path | What |
|---|---|
| `include/octet/`, `src/` | the server: classifier, replay reader, sockets, TLS over memory BIOs, HTTP head parser |
| `tools/mkcert.cpp` | a test CA and a server certificate for localhost, ECDSA P-256 |
| `tests/` | unit tests, an in-process TLS handshake test, and an integration test over real sockets |
| `bench/` | the four-arm benchmark, its analysis, and the in-memory micro-benchmark |
| `evidence/` | raw records and logs the document cites; see [`evidence/README.md`](evidence/README.md) |
| `docs/` | the course project in LaTeX; numbers come from `docs/generated/`, listings from the source |

## Build and test

C++23, CMake 3.25 or newer, OpenSSL 3.0 or newer, Ninja, Python 3 for the integration test.

Windows (Visual Studio Build Tools, OpenSSL from vcpkg, `VCPKG_ROOT` set):

```bat
scripts\build-windows.cmd
```

Linux:

```sh
cmake --preset linux-release
cmake --build --preset linux-release
ctest --preset linux-release
```

A `macos-release` preset exists but has **not** been built or run.

Tested on Windows 11 (MSVC 19.51, OpenSSL 3.6.4) and Ubuntu 24.04 in WSL2 (GCC 14.2, OpenSSL
3.0.13): all five suites pass, no compiler warnings at `/W4` or `-Wall -Wextra -Wpedantic
-Wconversion -Wshadow`.

## Run

```sh
octet-mkcert pki
octet --port 8443 --cert pki/server.pem --key pki/server.key
curl --cacert pki/ca.pem https://localhost:8443/
curl http://localhost:8443/
```

Both requests reach the same port. `octet --help` lists the options.

## What was measured

Whether first-octet detection costs anything, against a dedicated listener that skips it. The
short answer: in memory it is well under a microsecond per connection; end to end it is below
what the setup can resolve. The document has the tables, the intervals, the method, and the
limits (loopback, a Python client, Linux inside WSL2, a thread per connection). The first
Windows run measured from accept and turned out to measure thread start-up instead; it is kept,
and the document explains the change.

## Limits

This is a course project, not a production server. It serves the same content over cleartext
and TLS and sends no HSTS header, which is exactly the combination RFC 9325 section 3.2 warns
about. It has not been fuzzed or audited. See section 5 of the document.

## Licence

MIT. See [LICENSE](LICENSE).
