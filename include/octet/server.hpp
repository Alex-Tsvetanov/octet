// server.hpp: one listening socket, TLS and cleartext HTTP/1.1 on it, chosen per connection.

#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

#include "octet/classify.hpp"
#include "octet/net.hpp"
#include "octet/replay.hpp"
#include "octet/tls.hpp"

namespace octet
{

	struct ServerConfig
	{
		std::string host = "127.0.0.1";
		std::uint16_t port = 8443;
		int backlog = 512;

		// On: read the first octet and decide. Off: a dedicated listener that already
		// knows what arrives, which is what detection is measured against.
		bool detect = true;
		Wire dedicated = Wire::Tls;  // used only when detect is off

		std::optional<tls::Config> tls;  // no certificate: TLS clients are closed

		// One budget from accept until the transport is ready (the first octet, and the
		// whole handshake for TLS), and a second one for the request head after that.
		std::chrono::milliseconds handshake_timeout{5000};
		std::chrono::milliseconds request_timeout{5000};

		std::size_t max_connections = 256;  // beyond this, new connections are closed at once
		std::string record_path;            // CSV of per-connection timings; empty for none
		std::string label;                  // copied into every record, names the run
	};

	// What happened to one connection, and when. Times are microseconds since accept.
	struct ConnectionRecord
	{
		Wire wire = Wire::Unknown;
		std::string outcome;
		long long decide_us = -1;  // protocol known
		long long ready_us = -1;   // TLS handshake complete, or protocol known for cleartext
		long long served_us = -1;  // response written
		// Accept to the moment the connection thread starts running. The same in every
		// arm and not part of the mechanism, so measurements can subtract it.
		long long start_us = -1;
		std::size_t first_read = 0;
		std::string tls_version;
		std::string alpn;
	};

	class Server
	{
	public:
		explicit Server(ServerConfig config);

		// Creates the TLS context (if configured), opens the record file and binds.
		std::expected<void, std::string> open();

		[[nodiscard]] std::uint16_t port() const;

		// Accepts until the process ends. Each connection runs on its own thread.
		void serve_forever();

		// The whole life of one connection.
		ConnectionRecord handle(net::Socket sock, Clock::time_point accepted);

	private:
		void serve_tls(ReplayReader& raw, const tls::WriteFn& raw_out, Clock::time_point accepted,
		               const Deadline& handshake, ConnectionRecord& rec);
		void serve_http(ReplayReader& in, const tls::WriteFn& out, Clock::time_point ready,
		                std::string_view transport, ConnectionRecord& rec);
		void write_record(const ConnectionRecord& rec);

		ServerConfig config_;
		std::optional<tls::Context> tls_;
		net::Socket listener_;
		std::atomic<std::size_t> active_{0};

		std::mutex record_mutex_;
		std::ofstream record_;
	};

}  // namespace octet
