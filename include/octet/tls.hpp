// tls.hpp: the server side of TLS, over OpenSSL, driven through memory buffers.
//
// OpenSSL normally reads and writes the socket itself. Here it does not: it reads from a
// memory BIO that this code fills and writes to a memory BIO that this code drains. That
// is what lets the octets classification already consumed reach the handshake first, and
// it keeps the deadline in this code rather than inside the library.

#pragma once

#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>

#include "octet/deadline.hpp"
#include "octet/net.hpp"
#include "octet/replay.hpp"

// Forward declarations keep OpenSSL's headers out of every file that includes this one.
struct ssl_ctx_st;
struct ssl_st;
struct bio_st;

namespace octet::tls
{

	// Anywhere bytes can be written: a socket, or a test's in-memory peer.
	using WriteFn = std::function<net::Io(std::span<const std::uint8_t>, const Deadline&)>;

	enum class MinVersion : std::uint8_t
	{
		Tls12,
		Tls13
	};

	struct Config
	{
		std::string cert_chain_file;  // PEM: the server certificate first, then intermediates
		std::string key_file;         // PEM private key for the first certificate
		MinVersion min_version = MinVersion::Tls12;
		bool strict_alpn = true;      // refuse a client whose ALPN list lacks http/1.1
	};

	inline constexpr std::string_view kAlpnHttp11 = "http/1.1";

	// Looks for http/1.1 in a client's ALPN list, in wire format (RFC 7301 section 3.1:
	// a sequence of one-octet lengths, each followed by that many octets). Returns the
	// matching entry as a view into `client_list`, or nothing if it is absent or the list
	// is malformed.
	std::optional<std::span<const std::uint8_t>> choose_alpn(std::span<const std::uint8_t> client_list) noexcept;

	class Context
	{
	public:
		static std::expected<Context, std::string> create(const Config& config);

		Context(Context&&) noexcept;
		Context& operator=(Context&&) noexcept;
		~Context();

		[[nodiscard]] ssl_ctx_st* native() const noexcept { return ctx_; }

		// What the ALPN callback needs to know. Public only so that the callback, a free
		// function OpenSSL calls, can name it.
		struct AlpnPolicy;

	private:
		Context(ssl_ctx_st* ctx, std::unique_ptr<AlpnPolicy> policy) noexcept;

		ssl_ctx_st* ctx_ = nullptr;
		std::unique_ptr<AlpnPolicy> policy_;  // the ALPN callback's argument; stable address
	};

	class Session
	{
	public:
		// `in` delivers ciphertext, replayed classification octets first; `out` carries
		// ciphertext to the peer. Both must outlive the session.
		static std::expected<Session, std::string> create(const Context& ctx, ReplayReader& in, WriteFn out);

		Session(Session&&) noexcept;
		Session& operator=(Session&&) noexcept;
		~Session();

		// Runs the handshake to completion or failure. On failure any alert OpenSSL
		// produced has already been sent, so the peer learns why.
		std::expected<void, std::string> handshake(const Deadline& deadline);

		// Plaintext in and out, after the handshake.
		net::IoResult read(std::span<std::uint8_t> out, const Deadline& deadline);
		net::Io write_all(std::span<const std::uint8_t> in, const Deadline& deadline);

		// Sends close_notify. Does not wait for the peer's.
		void close_notify(const Deadline& deadline);

		[[nodiscard]] std::string version() const;
		[[nodiscard]] std::string cipher() const;
		[[nodiscard]] std::string alpn() const;

	private:
		Session(ssl_st* ssl, bio_st* rbio, bio_st* wbio, ReplayReader& in, WriteFn out) noexcept;

		net::Io flush(const Deadline& deadline);  // wbio to the peer
		net::Io feed(const Deadline& deadline);   // the peer to rbio

		ssl_st* ssl_ = nullptr;
		bio_st* rbio_ = nullptr;  // owned by ssl_
		bio_st* wbio_ = nullptr;  // owned by ssl_
		ReplayReader* in_ = nullptr;
		WriteFn out_;
	};

	// The text of the oldest error on this thread's OpenSSL queue, and clears the queue.
	std::string last_error();

}  // namespace octet::tls
