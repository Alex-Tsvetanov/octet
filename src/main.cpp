// main.cpp: the octet command line.

#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

#include "octet/net.hpp"
#include "octet/server.hpp"

namespace
{
	void usage()
	{
		std::fputs(
		    "usage: octet [options]\n"
		    "  --host ADDR               IPv4 address to listen on (default 127.0.0.1)\n"
		    "  --port N                  port, 0 for any free port (default 8443)\n"
		    "  --cert FILE --key FILE    PEM certificate chain and key; enables TLS\n"
		    "  --min-tls 1.2|1.3         lowest TLS version accepted (default 1.2)\n"
		    "  --no-strict-alpn          accept a client whose ALPN list lacks http/1.1\n"
		    "  --no-detect               dedicated listener: no first-octet classification\n"
		    "  --dedicated tls|cleartext what the dedicated listener expects (default tls)\n"
		    "  --handshake-timeout-ms N  budget from accept to a ready transport (default 5000)\n"
		    "  --request-timeout-ms N    budget for the request head after that (default 5000)\n"
		    "  --max-connections N       concurrent connections before refusing (default 256)\n"
		    "  --record FILE             append one CSV line per connection\n"
		    "  --label TEXT              first CSV column, names the run\n",
		    stderr);
	}

	bool parse_int(std::string_view text, long long& out)
	{
		const auto* end = text.data() + text.size();
		const auto r = std::from_chars(text.data(), end, out);
		return r.ec == std::errc{} && r.ptr == end;
	}
}  // namespace

int main(int argc, char** argv)
{
	octet::ServerConfig config;
	std::string cert;
	std::string key;
	octet::tls::MinVersion min_version = octet::tls::MinVersion::Tls12;
	bool strict_alpn = true;

	for (int i = 1; i < argc; ++i)
	{
		const std::string_view arg = argv[i];
		const bool has_value = i + 1 < argc;
		const std::string_view value = has_value ? argv[i + 1] : "";
		long long number = 0;

		if (arg == "--no-detect")
		{
			config.detect = false;
		}
		else if (arg == "--no-strict-alpn")
		{
			strict_alpn = false;
		}
		else if (!has_value)
		{
			usage();
			return 2;
		}
		else if (arg == "--host")
		{
			config.host = value;
			++i;
		}
		else if (arg == "--port" && parse_int(value, number) && number >= 0 && number <= 65535)
		{
			config.port = static_cast<std::uint16_t>(number);
			++i;
		}
		else if (arg == "--cert")
		{
			cert = value;
			++i;
		}
		else if (arg == "--key")
		{
			key = value;
			++i;
		}
		else if (arg == "--min-tls" && (value == "1.2" || value == "1.3"))
		{
			min_version = value == "1.3" ? octet::tls::MinVersion::Tls13 : octet::tls::MinVersion::Tls12;
			++i;
		}
		else if (arg == "--dedicated" && (value == "tls" || value == "cleartext"))
		{
			config.dedicated = value == "tls" ? octet::Wire::Tls : octet::Wire::Cleartext;
			++i;
		}
		else if (arg == "--handshake-timeout-ms" && parse_int(value, number) && number > 0)
		{
			config.handshake_timeout = std::chrono::milliseconds(number);
			++i;
		}
		else if (arg == "--request-timeout-ms" && parse_int(value, number) && number > 0)
		{
			config.request_timeout = std::chrono::milliseconds(number);
			++i;
		}
		else if (arg == "--max-connections" && parse_int(value, number) && number > 0)
		{
			config.max_connections = static_cast<std::size_t>(number);
			++i;
		}
		else if (arg == "--record")
		{
			config.record_path = value;
			++i;
		}
		else if (arg == "--label")
		{
			config.label = value;
			++i;
		}
		else
		{
			usage();
			return 2;
		}
	}

	if (cert.empty() != key.empty())
	{
		std::fputs("octet: --cert and --key go together\n", stderr);
		return 2;
	}
	if (!cert.empty())
	{
		config.tls = octet::tls::Config{cert, key, min_version, strict_alpn};
	}

	octet::net::Runtime runtime;
	octet::Server server(config);
	if (const auto opened = server.open(); !opened)
	{
		std::fprintf(stderr, "octet: %s\n", opened.error().c_str());
		return 1;
	}

	// The integration tests and the benchmark read this line to learn the port.
	std::printf("octet: listening on %s:%u (detection %s, tls %s)\n", config.host.c_str(),
	            static_cast<unsigned>(server.port()), config.detect ? "on" : "off", config.tls ? "on" : "off");
	std::fflush(stdout);

	server.serve_forever();
	return 0;
}
