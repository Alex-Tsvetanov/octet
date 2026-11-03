#include "octet/tls.hpp"

#include <array>
#include <cstring>
#include <utility>

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace octet::tls
{

	struct Context::AlpnPolicy
	{
		bool strict = true;
	};

	namespace
	{
		constexpr std::size_t kChunk = 16 * 1024;  // one maximum TLS record of plaintext

		// RFC 7301 section 3.2: the server picks one protocol from the client's list. If
		// it supports none of them it SHOULD answer with the no_application_protocol
		// alert. SSL_TLSEXT_ERR_ALERT_FATAL is how OpenSSL is told to send that alert.
		int alpn_select(SSL*, const unsigned char** out, unsigned char* outlen, const unsigned char* in,
		                unsigned int inlen, void* arg)
		{
			const auto* policy = static_cast<const Context::AlpnPolicy*>(arg);
			const auto choice = choose_alpn({in, inlen});
			if (choice)
			{
				*out = choice->data();
				*outlen = static_cast<unsigned char>(choice->size());
				return SSL_TLSEXT_ERR_OK;
			}
			return policy->strict ? SSL_TLSEXT_ERR_ALERT_FATAL : SSL_TLSEXT_ERR_NOACK;
		}
	}  // namespace

	std::string last_error()
	{
		const unsigned long code = ERR_get_error();
		ERR_clear_error();
		if (code == 0)
		{
			return "no OpenSSL error recorded";
		}
		std::array<char, 256> text{};
		ERR_error_string_n(code, text.data(), text.size());
		return text.data();
	}

	std::optional<std::span<const std::uint8_t>> choose_alpn(std::span<const std::uint8_t> client_list) noexcept
	{
		std::size_t i = 0;
		while (i < client_list.size())
		{
			const std::size_t len = client_list[i];
			if (len == 0 || i + 1 + len > client_list.size())
			{
				return std::nullopt;  // RFC 7301: empty names are invalid; overrun is malformed
			}
			const auto name = client_list.subspan(i + 1, len);
			if (len == kAlpnHttp11.size() && std::memcmp(name.data(), kAlpnHttp11.data(), len) == 0)
			{
				return name;
			}
			i += 1 + len;
		}
		return std::nullopt;
	}

	// ---- Context ---------------------------------------------------------------

	Context::Context(ssl_ctx_st* ctx, std::unique_ptr<AlpnPolicy> policy) noexcept
	    : ctx_(ctx), policy_(std::move(policy))
	{
	}

	Context::Context(Context&& other) noexcept
	    : ctx_(std::exchange(other.ctx_, nullptr)), policy_(std::move(other.policy_))
	{
	}

	Context& Context::operator=(Context&& other) noexcept
	{
		if (this != &other)
		{
			SSL_CTX_free(ctx_);
			ctx_ = std::exchange(other.ctx_, nullptr);
			policy_ = std::move(other.policy_);
		}
		return *this;
	}

	Context::~Context() { SSL_CTX_free(ctx_); }

	std::expected<Context, std::string> Context::create(const Config& config)
	{
		ERR_clear_error();
		SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
		if (ctx == nullptr)
		{
			return std::unexpected("SSL_CTX_new: " + last_error());
		}
		auto policy = std::make_unique<AlpnPolicy>();
		policy->strict = config.strict_alpn;
		Context result(ctx, std::move(policy));

		const int min = config.min_version == MinVersion::Tls13 ? TLS1_3_VERSION : TLS1_2_VERSION;
		if (SSL_CTX_set_min_proto_version(ctx, min) != 1)
		{
			return std::unexpected("minimum version: " + last_error());
		}

		// TLS 1.2 renegotiation is refused outright, and compression stays off (CRIME).
		// Neither exists in TLS 1.3; both still matter when a client negotiates 1.2.
		SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE);

		if (SSL_CTX_use_certificate_chain_file(ctx, config.cert_chain_file.c_str()) != 1)
		{
			return std::unexpected("certificate chain " + config.cert_chain_file + ": " + last_error());
		}
		if (SSL_CTX_use_PrivateKey_file(ctx, config.key_file.c_str(), SSL_FILETYPE_PEM) != 1)
		{
			return std::unexpected("private key " + config.key_file + ": " + last_error());
		}
		if (SSL_CTX_check_private_key(ctx) != 1)
		{
			return std::unexpected("the key does not match the certificate: " + last_error());
		}

		SSL_CTX_set_alpn_select_cb(ctx, alpn_select, result.policy_.get());
		return result;
	}

	// ---- Session ---------------------------------------------------------------

	Session::Session(ssl_st* ssl, bio_st* rbio, bio_st* wbio, ReplayReader& in, WriteFn out) noexcept
	    : ssl_(ssl), rbio_(rbio), wbio_(wbio), in_(&in), out_(std::move(out))
	{
	}

	Session::Session(Session&& other) noexcept
	    : ssl_(std::exchange(other.ssl_, nullptr)),
	      rbio_(std::exchange(other.rbio_, nullptr)),
	      wbio_(std::exchange(other.wbio_, nullptr)),
	      in_(other.in_),
	      out_(std::move(other.out_))
	{
	}

	Session& Session::operator=(Session&& other) noexcept
	{
		if (this != &other)
		{
			SSL_free(ssl_);
			ssl_ = std::exchange(other.ssl_, nullptr);
			rbio_ = std::exchange(other.rbio_, nullptr);
			wbio_ = std::exchange(other.wbio_, nullptr);
			in_ = other.in_;
			out_ = std::move(other.out_);
		}
		return *this;
	}

	Session::~Session() { SSL_free(ssl_); }  // frees both BIOs as well

	std::expected<Session, std::string> Session::create(const Context& ctx, ReplayReader& in, WriteFn out)
	{
		ERR_clear_error();
		SSL* ssl = SSL_new(ctx.native());
		if (ssl == nullptr)
		{
			return std::unexpected("SSL_new: " + last_error());
		}
		BIO* rbio = BIO_new(BIO_s_mem());
		BIO* wbio = BIO_new(BIO_s_mem());
		if (rbio == nullptr || wbio == nullptr)
		{
			BIO_free(rbio);
			BIO_free(wbio);
			SSL_free(ssl);
			return std::unexpected("BIO_new: " + last_error());
		}
		// An empty memory BIO reports "retry" rather than end of file, which is what turns
		// "no bytes yet" into SSL_ERROR_WANT_READ instead of a fatal error.
		BIO_set_mem_eof_return(rbio, -1);
		SSL_set_bio(ssl, rbio, wbio);  // ssl now owns both
		SSL_set_accept_state(ssl);
		return Session(ssl, rbio, wbio, in, std::move(out));
	}

	net::Io Session::flush(const Deadline& deadline)
	{
		std::array<std::uint8_t, kChunk> buf{};
		for (;;)
		{
			const int n = BIO_read(wbio_, buf.data(), static_cast<int>(buf.size()));
			if (n <= 0)
			{
				return net::Io::Ok;  // drained
			}
			const auto status = out_(std::span<const std::uint8_t>(buf.data(), static_cast<std::size_t>(n)), deadline);
			if (status != net::Io::Ok)
			{
				return status;
			}
		}
	}

	net::Io Session::feed(const Deadline& deadline)
	{
		std::array<std::uint8_t, kChunk> buf{};
		const auto r = in_->read(buf, deadline);
		if (r.status != net::Io::Ok)
		{
			return r.status;
		}
		if (BIO_write(rbio_, buf.data(), static_cast<int>(r.bytes)) != static_cast<int>(r.bytes))
		{
			return net::Io::Error;
		}
		return net::Io::Ok;
	}

	std::expected<void, std::string> Session::handshake(const Deadline& deadline)
	{
		for (;;)
		{
			ERR_clear_error();
			const int rc = SSL_do_handshake(ssl_);
			const int err = rc == 1 ? SSL_ERROR_NONE : SSL_get_error(ssl_, rc);
			const std::string reason = (err == SSL_ERROR_NONE || err == SSL_ERROR_WANT_READ) ? "" : last_error();

			// Whatever OpenSSL produced goes out first: the next flight on success, the
			// alert on failure. An alert that is never sent leaves the client guessing.
			const auto sent = flush(deadline);

			if (err == SSL_ERROR_NONE)
			{
				if (sent != net::Io::Ok)
				{
					return std::unexpected("handshake completed but the final flight was not sent");
				}
				return {};
			}
			if (err != SSL_ERROR_WANT_READ)
			{
				return std::unexpected("handshake failed: " + reason);
			}
			if (sent != net::Io::Ok)
			{
				return std::unexpected("could not send a handshake flight");
			}
			switch (feed(deadline))
			{
				case net::Io::Ok:
					break;
				case net::Io::Timeout:
					return std::unexpected("timeout");
				case net::Io::Closed:
					return std::unexpected("peer closed during the handshake");
				case net::Io::Error:
					return std::unexpected("socket error during the handshake");
			}
		}
	}

	net::IoResult Session::read(std::span<std::uint8_t> out, const Deadline& deadline)
	{
		for (;;)
		{
			ERR_clear_error();
			const int n = SSL_read(ssl_, out.data(), static_cast<int>(out.size()));
			const int err = n > 0 ? SSL_ERROR_NONE : SSL_get_error(ssl_, n);
			// TLS 1.3 servers send session tickets after the handshake; let them out.
			const auto sent = flush(deadline);
			if (err == SSL_ERROR_NONE)
			{
				return {net::Io::Ok, static_cast<std::size_t>(n)};
			}
			if (err == SSL_ERROR_ZERO_RETURN)
			{
				return {net::Io::Closed, 0};  // the peer's close_notify
			}
			if (err != SSL_ERROR_WANT_READ || sent != net::Io::Ok)
			{
				return {net::Io::Error, 0};
			}
			const auto fed = feed(deadline);
			if (fed != net::Io::Ok)
			{
				return {fed, 0};
			}
		}
	}

	net::Io Session::write_all(std::span<const std::uint8_t> in, const Deadline& deadline)
	{
		while (!in.empty())
		{
			ERR_clear_error();
			const int n = SSL_write(ssl_, in.data(), static_cast<int>(in.size()));
			if (n <= 0)
			{
				return net::Io::Error;  // a memory BIO never blocks a write
			}
			in = in.subspan(static_cast<std::size_t>(n));
			const auto sent = flush(deadline);
			if (sent != net::Io::Ok)
			{
				return sent;
			}
		}
		return net::Io::Ok;
	}

	void Session::close_notify(const Deadline& deadline)
	{
		ERR_clear_error();
		SSL_shutdown(ssl_);
		flush(deadline);
	}

	std::string Session::version() const { return SSL_get_version(ssl_); }

	std::string Session::cipher() const
	{
		const char* name = SSL_get_cipher_name(ssl_);
		return name != nullptr ? name : "";
	}

	std::string Session::alpn() const
	{
		const unsigned char* data = nullptr;
		unsigned int len = 0;
		SSL_get0_alpn_selected(ssl_, &data, &len);
		return std::string(reinterpret_cast<const char*>(data), len);
	}

}  // namespace octet::tls
