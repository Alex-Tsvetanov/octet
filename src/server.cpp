#include "octet/server.hpp"

#include <span>
#include <thread>
#include <utility>
#include <vector>

#include "octet/http.hpp"

namespace octet
{

	namespace
	{
		// How much the classification read asks for. One octet decides; asking for more
		// costs nothing and usually brings the whole ClientHello or request line in the
		// same system call. Whatever arrives is replayed, so nothing depends on the size.
		constexpr std::size_t kFirstRead = 2048;

		long long micros_since(Clock::time_point t0)
		{
			return std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - t0).count();
		}

		std::string outcome_of(net::Io io)
		{
			switch (io)
			{
				case net::Io::Ok:
					return "ok";
				case net::Io::Closed:
					return "closed";
				case net::Io::Timeout:
					return "timeout";
				case net::Io::Error:
					break;
			}
			return "io_error";
		}

		std::string outcome_of(http::Error e)
		{
			switch (e)
			{
				case http::Error::BadRequest:
					return "bad_request";
				case http::Error::TooLarge:
					return "too_large";
				case http::Error::Timeout:
					return "timeout";
				case http::Error::Closed:
					return "closed";
				case http::Error::Io:
					break;
			}
			return "io_error";
		}

		std::span<const std::uint8_t> bytes_of(std::string_view s)
		{
			return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
		}
	}  // namespace

	Server::Server(ServerConfig config) : config_(std::move(config)) {}

	std::expected<void, std::string> Server::open()
	{
		if (config_.tls)
		{
			auto ctx = tls::Context::create(*config_.tls);
			if (!ctx)
			{
				return std::unexpected(ctx.error());
			}
			tls_.emplace(std::move(*ctx));
		}
		if (!config_.detect && config_.dedicated == Wire::Tls && !tls_)
		{
			return std::unexpected("a dedicated TLS listener needs a certificate and key");
		}

		if (!config_.record_path.empty())
		{
			record_.open(config_.record_path, std::ios::app);
			if (!record_)
			{
				return std::unexpected("cannot open " + config_.record_path);
			}
		}

		auto listener = net::listen_tcp(config_.host, config_.port, config_.backlog);
		if (!listener)
		{
			return std::unexpected(listener.error());
		}
		listener_ = std::move(*listener);
		return {};
	}

	std::uint16_t Server::port() const { return net::local_port(listener_); }

	void Server::serve_forever()
	{
		for (;;)
		{
			auto conn = net::accept(listener_);
			const auto accepted = Clock::now();
			if (!conn)
			{
				continue;  // a failed accept affects one connection, not the listener
			}

			// A thread per connection is simple, and the bound keeps it safe: without it a
			// peer that opens connections and says nothing could exhaust threads long
			// before any deadline fires.
			if (active_.load() >= config_.max_connections)
			{
				ConnectionRecord rec;
				rec.outcome = "refused_limit";
				write_record(rec);
				continue;  // the socket closes as `conn` goes out of scope
			}
			++active_;
			std::thread([this, sock = std::move(*conn), accepted]() mutable {
				const auto rec = handle(std::move(sock), accepted);
				write_record(rec);
				--active_;
			}).detach();
		}
	}

	ConnectionRecord Server::handle(net::Socket sock, Clock::time_point accepted)
	{
		ConnectionRecord rec;
		const Deadline handshake(accepted + config_.handshake_timeout);

		std::vector<std::uint8_t> first;
		Wire wire = config_.dedicated;
		if (config_.detect)
		{
			first.resize(kFirstRead);
			const auto r = net::recv_some(sock, first, handshake);
			if (r.status != net::Io::Ok)
			{
				// Silent until the deadline, or gone before saying anything.
				rec.outcome = outcome_of(r.status);
				return rec;
			}
			first.resize(r.bytes);
			rec.first_read = r.bytes;
			wire = classify(first);
		}
		rec.wire = wire;
		rec.decide_us = micros_since(accepted);

		ReplayReader raw(std::move(first), [&sock](std::span<std::uint8_t> out, const Deadline& d) {
			return net::recv_some(sock, out, d);
		});
		const tls::WriteFn raw_out = [&sock](std::span<const std::uint8_t> in, const Deadline& d) {
			return net::send_all(sock, in, d);
		};

		switch (wire)
		{
			case Wire::Tls:
				serve_tls(raw, raw_out, accepted, handshake, rec);
				break;
			case Wire::Cleartext:
				rec.ready_us = rec.decide_us;
				serve_http(raw, raw_out, Clock::now(), "cleartext", rec);
				break;
			case Wire::Unknown:
				// Neither a TLS record nor an HTTP method. Nothing sensible can be said
				// back in a protocol the peer did not speak, so it gets no reply at all.
				rec.outcome = "unknown_protocol";
				break;
		}

		sock.shutdown_write();
		return rec;  // `sock` closes here
	}

	void Server::serve_tls(ReplayReader& raw, const tls::WriteFn& raw_out, Clock::time_point accepted,
	                       const Deadline& handshake, ConnectionRecord& rec)
	{
		if (!tls_)
		{
			// A TLS client reached a server with no certificate. A cleartext reply would
			// be unreadable to it, so the connection is closed.
			rec.outcome = "tls_unavailable";
			return;
		}

		auto session = tls::Session::create(*tls_, raw, raw_out);
		if (!session)
		{
			rec.outcome = "tls_failed";
			return;
		}
		// The handshake runs inside the same deadline as classification. A peer that
		// sends 0x16 and then stops is the same threat as one that sends nothing.
		const auto done = session->handshake(handshake);
		if (!done)
		{
			rec.outcome = done.error() == "timeout" ? "timeout" : "tls_failed";
			return;
		}
		rec.ready_us = micros_since(accepted);
		rec.tls_version = session->version();
		rec.alpn = session->alpn();

		ReplayReader plain({}, [&session](std::span<std::uint8_t> out, const Deadline& d) {
			return session->read(out, d);
		});
		const tls::WriteFn plain_out = [&session](std::span<const std::uint8_t> in, const Deadline& d) {
			return session->write_all(in, d);
		};
		serve_http(plain, plain_out, Clock::now(), "tls", rec);
		session->close_notify(Deadline(std::chrono::milliseconds(200)));
	}

	void Server::serve_http(ReplayReader& in, const tls::WriteFn& out, Clock::time_point ready,
	                        std::string_view transport, ConnectionRecord& rec)
	{
		const Deadline request(ready + config_.request_timeout);
		const auto req = http::read_request(in, request);
		if (!req)
		{
			const int status = http::status_of(req.error());
			if (status != 0)
			{
				const auto reason = status == 431 ? "Request Header Fields Too Large" : "Bad Request";
				out(bytes_of(http::make_response(status, reason, "")), request);
			}
			rec.outcome = outcome_of(req.error());
			return;
		}

		// Classification let in anything that opens with an upper-case letter, and the
		// parser accepted any well-formed method token. Only GET is served; any other
		// method is answered as not implemented (RFC 9110 section 15.6.2).
		if (req->method != "GET")
		{
			const auto sent = out(bytes_of(http::make_response(501, "Not Implemented", "")), request);
			rec.served_us = rec.ready_us + micros_since(ready);
			rec.outcome = sent == net::Io::Ok ? "not_implemented" : outcome_of(sent);
			return;
		}

		const std::string body = "octet: " + std::string(transport) + "\n";
		const auto sent = out(bytes_of(http::make_response(200, "OK", body)), request);
		rec.served_us = rec.ready_us + micros_since(ready);
		rec.outcome = sent == net::Io::Ok ? "served" : outcome_of(sent);
	}

	void Server::write_record(const ConnectionRecord& rec)
	{
		if (!record_.is_open())
		{
			return;
		}
		std::lock_guard lock(record_mutex_);
		record_ << config_.label << ',' << to_string(rec.wire) << ',' << rec.outcome << ',' << rec.decide_us << ','
		        << rec.ready_us << ',' << rec.served_us << ',' << rec.first_read << ',' << rec.tls_version << ','
		        << rec.alpn << '\n';
		record_.flush();  // a benchmark stops the server by ending the process
	}

}  // namespace octet
