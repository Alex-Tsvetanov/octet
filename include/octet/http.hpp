// http.hpp: just enough HTTP/1.1 to answer one request and close.
//
// This is not a general HTTP server. It reads one request head, checks the request line
// strictly, ignores the header fields, and answers with a short text body. Strictness is
// the point: everything classification let through as "cleartext" on the strength of one
// upper-case letter is validated here.

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

#include "octet/deadline.hpp"
#include "octet/replay.hpp"

namespace octet::http
{

	inline constexpr std::size_t kMaxHead = 8192;   // request line plus header fields
	inline constexpr std::size_t kMaxMethod = 16;

	struct Request
	{
		std::string method;
		std::string target;
		std::string version;
	};

	enum class Error : std::uint8_t
	{
		BadRequest,  // 400: malformed request line or header section
		TooLarge,    // 431: head longer than kMaxHead
		Timeout,     // the deadline passed before the head was complete
		Closed,      // the peer closed before the head was complete
		Io           // a socket or TLS error
	};

	// Parses a complete head, the bytes up to and excluding the blank line.
	std::expected<Request, Error> parse_head(std::string_view head);

	// Reads until the blank line that ends the head, then parses it.
	std::expected<Request, Error> read_request(ReplayReader& in, const Deadline& deadline);

	// A complete response with Content-Length and Connection: close.
	std::string make_response(int status, std::string_view reason, std::string_view body);

	// Status line for an error, so the caller can answer before closing.
	int status_of(Error e) noexcept;

}  // namespace octet::http
