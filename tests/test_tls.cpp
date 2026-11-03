// test_tls.cpp: real TLS handshakes between an OpenSSL client and the octet server
// session, inside one process and one thread, with no sockets.
//
// The trick is the read function handed to the server: when the server needs bytes and
// none are queued, it runs the client one step, which consumes whatever the server sent
// and produces the next flight. So the two sides take turns without a second thread.

#include <algorithm>
#include <climits>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "check.hpp"
#include "octet/classify.hpp"
#include "octet/pki.hpp"
#include "octet/tls.hpp"

using octet::Deadline;
using octet::ReplayReader;
using octet::net::Io;
using octet::net::IoResult;

namespace
{
	struct Client
	{
		SSL_CTX* ctx = nullptr;
		SSL* ssl = nullptr;
		BIO* rbio = nullptr;
		BIO* wbio = nullptr;
		std::deque<std::uint8_t> to_server;
		std::deque<std::uint8_t> to_client;
		std::size_t dribble = SIZE_MAX;  // most octets the server may read per call
		std::string plaintext;           // what the client has read after the handshake
		unsigned long last_error = 0;    // the client OpenSSL error from its latest step

		~Client()
		{
			SSL_free(ssl);
			SSL_CTX_free(ctx);
		}
	};

	struct ClientOptions
	{
		std::vector<std::string> alpn;
		int max_version = 0;  // 0: library default (TLS 1.3)
		std::string expected_host = "localhost";
	};

	std::unique_ptr<Client> make_client(const octet::pki::Files& pki, const ClientOptions& opt)
	{
		auto c = std::make_unique<Client>();
		c->ctx = SSL_CTX_new(TLS_client_method());
		SSL_CTX_load_verify_locations(c->ctx, pki.ca_cert.string().c_str(), nullptr);
		SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, nullptr);
		if (opt.max_version != 0)
		{
			SSL_CTX_set_max_proto_version(c->ctx, opt.max_version);
		}
		c->ssl = SSL_new(c->ctx);
		SSL_set1_host(c->ssl, opt.expected_host.c_str());
		SSL_set_tlsext_host_name(c->ssl, opt.expected_host.c_str());
		if (!opt.alpn.empty())
		{
			std::vector<unsigned char> wire;
			for (const auto& name : opt.alpn)
			{
				wire.push_back(static_cast<unsigned char>(name.size()));
				wire.insert(wire.end(), name.begin(), name.end());
			}
			SSL_set_alpn_protos(c->ssl, wire.data(), static_cast<unsigned int>(wire.size()));
		}
		c->rbio = BIO_new(BIO_s_mem());
		c->wbio = BIO_new(BIO_s_mem());
		BIO_set_mem_eof_return(c->rbio, -1);
		SSL_set_bio(c->ssl, c->rbio, c->wbio);
		SSL_set_connect_state(c->ssl);
		return c;
	}

	void drain_client_output(Client& c)
	{
		unsigned char buf[4096];
		int n = 0;
		while ((n = BIO_read(c.wbio, buf, sizeof buf)) > 0)
		{
			c.to_server.insert(c.to_server.end(), buf, buf + n);
		}
	}

	// One turn of the client: take what the server sent, advance, queue the reply.
	void step(Client& c)
	{
		if (!c.to_client.empty())
		{
			const std::vector<std::uint8_t> in(c.to_client.begin(), c.to_client.end());
			c.to_client.clear();
			BIO_write(c.rbio, in.data(), static_cast<int>(in.size()));
		}
		ERR_clear_error();
		if (!SSL_is_init_finished(c.ssl))
		{
			SSL_do_handshake(c.ssl);
		}
		else
		{
			char buf[4096];
			int n = 0;
			while ((n = SSL_read(c.ssl, buf, sizeof buf)) > 0)
			{
				c.plaintext.append(buf, static_cast<std::size_t>(n));
			}
		}
		c.last_error = ERR_peek_last_error();
		drain_client_output(c);
	}

	octet::ReadFn server_reads_from(Client& c)
	{
		return [&c](std::span<std::uint8_t> out, const Deadline&) -> IoResult {
			if (c.to_server.empty())
			{
				step(c);
			}
			if (c.to_server.empty())
			{
				return {Io::Closed, 0};  // the client has nothing more to say
			}
			const std::size_t n = std::min({out.size(), c.to_server.size(), c.dribble});
			std::copy_n(c.to_server.begin(), n, out.begin());
			c.to_server.erase(c.to_server.begin(), c.to_server.begin() + static_cast<std::ptrdiff_t>(n));
			return {Io::Ok, n};
		};
	}

	octet::tls::WriteFn server_writes_to(Client& c)
	{
		return [&c](std::span<const std::uint8_t> in, const Deadline&) {
			c.to_client.insert(c.to_client.end(), in.begin(), in.end());
			return Io::Ok;
		};
	}

	octet::tls::Context server_context(const octet::pki::Files& pki, bool strict,
	                                   octet::tls::MinVersion min = octet::tls::MinVersion::Tls12)
	{
		auto ctx = octet::tls::Context::create(
		    {pki.server_chain.string(), pki.server_key.string(), min, strict});
		CHECK(ctx.has_value());
		return std::move(*ctx);
	}

	struct Outcome
	{
		bool ok = false;
		std::string version;
		std::string alpn;
	};

	// Runs a whole handshake. The client speaks first; its first octet is taken out and
	// replayed, exactly as the server does after classification.
	Outcome handshake(Client& c, const octet::tls::Context& ctx)
	{
		step(c);  // the ClientHello
		std::vector<std::uint8_t> first;
		if (!c.to_server.empty())
		{
			first.push_back(c.to_server.front());
			c.to_server.pop_front();
		}
		CHECK(octet::classify(first) == octet::Wire::Tls);

		ReplayReader in(std::move(first), server_reads_from(c));
		auto session = octet::tls::Session::create(ctx, in, server_writes_to(c));
		CHECK(session.has_value());
		const Deadline d(std::chrono::seconds(5));
		const bool ok = session->handshake(d).has_value();
		step(c);  // the client reads the server last flight, or its alert
		return {ok, ok ? session->version() : "", ok ? session->alpn() : ""};
	}

	std::filesystem::path temp_dir()
	{
		std::random_device rd;
		auto dir = std::filesystem::temp_directory_path() / ("octet-test-" + std::to_string(rd()));
		return dir;
	}

	void alpn_parsing()
	{
		using octet::tls::choose_alpn;
		const std::vector<std::uint8_t> both{2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
		const auto pick = choose_alpn(both);
		CHECK(pick.has_value() && pick->size() == 8 && pick->data() == both.data() + 4);

		const std::vector<std::uint8_t> h2_only{2, 'h', '2'};
		CHECK(!choose_alpn(h2_only).has_value());

		const std::vector<std::uint8_t> overrun{9, 'h', 't', 't', 'p', '/', '1', '.', '1'};
		CHECK(!choose_alpn(overrun).has_value());

		const std::vector<std::uint8_t> empty_name{0, 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
		CHECK(!choose_alpn(empty_name).has_value());

		CHECK(!choose_alpn({}).has_value());
	}

	void handshake_one_octet_at_a_time(const octet::pki::Files& pki)
	{
		const auto ctx = server_context(pki, true);
		auto c = make_client(pki, {{"h2", "http/1.1"}});
		c->dribble = 1;  // the server gets the ClientHello one octet per read
		const auto out = handshake(*c, ctx);
		CHECK(out.ok);
		CHECK(out.version == "TLSv1.3");
		CHECK(out.alpn == "http/1.1");
		CHECK(SSL_is_init_finished(c->ssl) == 1);
		CHECK(SSL_get_verify_result(c->ssl) == X509_V_OK);  // the chain to the test CA held
	}

	void application_data_both_ways(const octet::pki::Files& pki)
	{
		const auto ctx = server_context(pki, true);
		auto c = make_client(pki, {{"http/1.1"}});

		step(*c);
		std::vector<std::uint8_t> first{c->to_server.front()};
		c->to_server.pop_front();
		ReplayReader in(std::move(first), server_reads_from(*c));
		auto session = octet::tls::Session::create(ctx, in, server_writes_to(*c));
		const Deadline d(std::chrono::seconds(5));
		CHECK(session->handshake(d).has_value());
		step(*c);

		const std::string request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
		CHECK(SSL_write(c->ssl, request.data(), static_cast<int>(request.size())) > 0);
		drain_client_output(*c);

		std::vector<std::uint8_t> buf(256);
		const auto r = session->read(buf, d);
		CHECK(r.status == Io::Ok);
		CHECK(std::string(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(r.bytes)) == request);

		const std::string reply = "HTTP/1.1 200 OK\r\n\r\n";
		CHECK(session->write_all({reinterpret_cast<const std::uint8_t*>(reply.data()), reply.size()}, d) == Io::Ok);
		step(*c);
		CHECK(c->plaintext == reply);
	}

	void strict_alpn_sends_the_alert(const octet::pki::Files& pki)
	{
		const auto ctx = server_context(pki, true);
		auto c = make_client(pki, {{"h2"}});
		const auto out = handshake(*c, ctx);
		CHECK(!out.ok);
		// RFC 7301 section 3.2: no_application_protocol, alert 120. The client must have
		// received it, not merely seen the connection end.
		CHECK(ERR_GET_REASON(c->last_error) == SSL_AD_REASON_OFFSET + SSL_AD_NO_APPLICATION_PROTOCOL);
	}

	void lenient_alpn_and_no_alpn(const octet::pki::Files& pki)
	{
		const auto lenient = server_context(pki, false);
		auto h2 = make_client(pki, {{"h2"}});
		const auto a = handshake(*h2, lenient);
		CHECK(a.ok && a.alpn.empty());

		const auto strict = server_context(pki, true);
		auto none = make_client(pki, {});
		const auto b = handshake(*none, strict);
		CHECK(b.ok && b.alpn.empty());  // no extension offered: nothing to refuse
	}

	void version_floor(const octet::pki::Files& pki)
	{
		const auto floor12 = server_context(pki, true, octet::tls::MinVersion::Tls12);
		auto old = make_client(pki, {{"http/1.1"}, TLS1_2_VERSION});
		const auto a = handshake(*old, floor12);
		CHECK(a.ok && a.version == "TLSv1.2");

		const auto floor13 = server_context(pki, true, octet::tls::MinVersion::Tls13);
		auto old2 = make_client(pki, {{"http/1.1"}, TLS1_2_VERSION});
		CHECK(!handshake(*old2, floor13).ok);
	}

	void wrong_name_fails_at_the_client(const octet::pki::Files& pki)
	{
		// The certificate names localhost. A client that expected another name rejects
		// it: the check happens in the client, which is why the server cannot skip it.
		const auto ctx = server_context(pki, true);
		auto c = make_client(pki, {{"http/1.1"}, 0, "example.com"});
		const auto out = handshake(*c, ctx);
		CHECK(!out.ok);
		CHECK(SSL_get_verify_result(c->ssl) == X509_V_ERR_HOSTNAME_MISMATCH);
	}
}  // namespace

int main()
{
	alpn_parsing();

	const auto dir = temp_dir();
	const auto pki = octet::pki::make_test_pki(dir);
	CHECK(pki.has_value());
	if (pki)
	{
		handshake_one_octet_at_a_time(*pki);
		application_data_both_ways(*pki);
		strict_alpn_sends_the_alert(*pki);
		lenient_alpn_and_no_alpn(*pki);
		version_floor(*pki);
		wrong_name_fails_at_the_client(*pki);
	}
	std::error_code ec;
	std::filesystem::remove_all(dir, ec);
	return octet_test::report("tls");
}
