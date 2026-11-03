#include "octet/http.hpp"

#include <array>

namespace octet::http
{

	namespace
	{
		bool is_upper(char c) { return c >= 'A' && c <= 'Z'; }

		// A request target in origin form: starts with '/', visible ASCII only.
		bool valid_target(std::string_view t)
		{
			if (t.empty() || t.front() != '/')
			{
				return false;
			}
			for (const char c : t)
			{
				const auto u = static_cast<unsigned char>(c);
				if (u <= 0x20 || u >= 0x7F)
				{
					return false;
				}
			}
			return true;
		}

		bool valid_field_line(std::string_view line)
		{
			// Obsolete line folding (RFC 9112 section 5.2) is rejected, not unfolded.
			if (line.empty() || line.front() == ' ' || line.front() == '\t')
			{
				return false;
			}
			const auto colon = line.find(':');
			if (colon == std::string_view::npos || colon == 0)
			{
				return false;
			}
			// No whitespace between the field name and the colon (RFC 9112 section 5.1).
			const char before = line[colon - 1];
			return before != ' ' && before != '\t';
		}
	}  // namespace

	std::expected<Request, Error> parse_head(std::string_view head)
	{
		const auto eol = head.find("\r\n");
		const std::string_view line = head.substr(0, eol);

		const auto sp1 = line.find(' ');
		if (sp1 == std::string_view::npos || sp1 == 0 || sp1 > kMaxMethod)
		{
			return std::unexpected(Error::BadRequest);
		}
		const auto sp2 = line.find(' ', sp1 + 1);
		if (sp2 == std::string_view::npos || line.find(' ', sp2 + 1) != std::string_view::npos)
		{
			return std::unexpected(Error::BadRequest);
		}

		const std::string_view method = line.substr(0, sp1);
		const std::string_view target = line.substr(sp1 + 1, sp2 - sp1 - 1);
		const std::string_view version = line.substr(sp2 + 1);

		for (const char c : method)
		{
			if (!is_upper(c))
			{
				return std::unexpected(Error::BadRequest);
			}
		}
		if (!valid_target(target) || (version != "HTTP/1.1" && version != "HTTP/1.0"))
		{
			return std::unexpected(Error::BadRequest);
		}

		// Every header field line must at least look like one.
		std::string_view rest = eol == std::string_view::npos ? std::string_view{} : head.substr(eol + 2);
		while (!rest.empty())
		{
			const auto next = rest.find("\r\n");
			const std::string_view field = rest.substr(0, next);
			if (!valid_field_line(field))
			{
				return std::unexpected(Error::BadRequest);
			}
			rest = next == std::string_view::npos ? std::string_view{} : rest.substr(next + 2);
		}

		return Request{std::string(method), std::string(target), std::string(version)};
	}

	std::expected<Request, Error> read_request(ReplayReader& in, const Deadline& deadline)
	{
		std::string head;
		std::array<std::uint8_t, 1024> chunk{};
		for (;;)
		{
			const auto end = head.find("\r\n\r\n");
			if (end != std::string::npos)
			{
				// The limit applies to the head, wherever the read that completed it
				// happened to stop. Checking only the bytes buffered so far lets an
				// oversized head through whenever its last chunk also carries the end.
				if (end > kMaxHead)
				{
					return std::unexpected(Error::TooLarge);
				}
				return parse_head(std::string_view(head).substr(0, end));
			}
			if (head.size() > kMaxHead)
			{
				return std::unexpected(Error::TooLarge);
			}

			const auto r = in.read(chunk, deadline);
			switch (r.status)
			{
				case net::Io::Ok:
					head.append(reinterpret_cast<const char*>(chunk.data()), r.bytes);
					break;
				case net::Io::Timeout:
					return std::unexpected(Error::Timeout);
				case net::Io::Closed:
					return std::unexpected(Error::Closed);
				case net::Io::Error:
					return std::unexpected(Error::Io);
			}
		}
	}

	std::string make_response(int status, std::string_view reason, std::string_view body)
	{
		std::string out;
		out.reserve(128 + body.size());
		out += "HTTP/1.1 ";
		out += std::to_string(status);
		out += ' ';
		out += reason;
		out += "\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ";
		out += std::to_string(body.size());
		out += "\r\nConnection: close\r\n\r\n";
		out += body;
		return out;
	}

	int status_of(Error e) noexcept
	{
		switch (e)
		{
			case Error::TooLarge:
				return 431;
			case Error::BadRequest:
				return 400;
			case Error::Timeout:
			case Error::Closed:
			case Error::Io:
				break;
		}
		return 0;  // nothing to answer: the peer is gone or silent
	}

}  // namespace octet::http
