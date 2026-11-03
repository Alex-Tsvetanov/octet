// classify.hpp: decide TLS or cleartext HTTP from the first octet of a connection.
//
// A TLS connection opens with a TLSPlaintext record (RFC 8446 section 5.1). Its first
// field is ContentType, and the first record a client sends carries the ClientHello, so
// that octet is handshake(22) = 0x16. An HTTP/1.x request opens with its method token
// (RFC 9110 section 9), and every registered method is upper-case ASCII. The HTTP/2
// connection preface opens with "PRI" (RFC 9113 section 3.4), also upper-case. 0x16 is
// a control character and never a letter, so one octet separates the two sets.
//
// The function only routes. It does not prove that the bytes are a valid ClientHello or
// a valid request line; the TLS library and the HTTP parser downstream do that.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace octet
{

	enum class Wire : std::uint8_t
	{
		Tls,        // first octet is ContentType handshake (0x16)
		Cleartext,  // first octet is an upper-case ASCII letter
		Unknown     // anything else, including no data at all
	};

	// TLS ContentType values, RFC 8446 section 5.1 (and RFC 5246 section 6.2.1).
	inline constexpr std::uint8_t kContentChangeCipherSpec = 0x14;
	inline constexpr std::uint8_t kContentAlert = 0x15;
	inline constexpr std::uint8_t kContentHandshake = 0x16;
	inline constexpr std::uint8_t kContentApplicationData = 0x17;

	[[nodiscard]] constexpr Wire classify(std::span<const std::uint8_t> first) noexcept
	{
		if (first.empty())
		{
			return Wire::Unknown;
		}
		const std::uint8_t octet = first.front();
		if (octet == kContentHandshake)
		{
			return Wire::Tls;
		}
		if (octet >= 'A' && octet <= 'Z')
		{
			return Wire::Cleartext;
		}
		return Wire::Unknown;
	}

	[[nodiscard]] constexpr std::string_view to_string(Wire w) noexcept
	{
		switch (w)
		{
			case Wire::Tls:
				return "tls";
			case Wire::Cleartext:
				return "cleartext";
			case Wire::Unknown:
				break;
		}
		return "unknown";
	}

}  // namespace octet
