#include <cstdint>
#include <string_view>
#include <vector>

#include "check.hpp"
#include "octet/classify.hpp"

using octet::classify;
using octet::Wire;

namespace
{
	Wire of(std::string_view text)
	{
		const std::vector<std::uint8_t> bytes(text.begin(), text.end());
		return classify(bytes);
	}

	Wire of_octet(std::uint8_t b)
	{
		const std::uint8_t one[1] = {b};
		return classify(one);
	}

	// The claim the whole design rests on: over every possible first octet, the TLS set
	// and the cleartext set are disjoint, and each is exactly what it should be.
	void every_octet()
	{
		int tls = 0;
		int clear = 0;
		for (int b = 0; b <= 0xFF; ++b)
		{
			const Wire w = of_octet(static_cast<std::uint8_t>(b));
			const bool is_letter = b >= 'A' && b <= 'Z';
			CHECK((w == Wire::Tls) == (b == 0x16));
			CHECK((w == Wire::Cleartext) == is_letter);
			tls += w == Wire::Tls ? 1 : 0;
			clear += w == Wire::Cleartext ? 1 : 0;
		}
		CHECK(tls == 1);
		CHECK(clear == 26);
	}

	void http_methods()
	{
		// RFC 9110 section 9 methods, the WebDAV ones from RFC 4918, and the HTTP/2
		// preface (RFC 9113 section 3.4).
		for (std::string_view line : {"GET / HTTP/1.1", "HEAD / HTTP/1.1", "POST / HTTP/1.1", "PUT / HTTP/1.1",
		                              "DELETE / HTTP/1.1", "CONNECT host:443 HTTP/1.1", "OPTIONS * HTTP/1.1",
		                              "TRACE / HTTP/1.1", "PATCH / HTTP/1.1", "PROPFIND / HTTP/1.1",
		                              "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"})
		{
			CHECK(of(line) == Wire::Cleartext);
		}
	}

	void tls_records()
	{
		// A ClientHello record header: handshake(22), legacy version 3.1, a length.
		const std::vector<std::uint8_t> hello{0x16, 0x03, 0x01, 0x00, 0xF8, 0x01};
		CHECK(classify(hello) == Wire::Tls);

		// No other ContentType can open a connection. Seeing one first means the peer
		// is not starting a TLS session, so it is not routed to the TLS layer.
		CHECK(of_octet(octet::kContentChangeCipherSpec) == Wire::Unknown);
		CHECK(of_octet(octet::kContentAlert) == Wire::Unknown);
		CHECK(of_octet(octet::kContentApplicationData) == Wire::Unknown);

		// An SSL 2.0 style ClientHello starts with a length octet with the top bit set.
		// SSL 2.0 is prohibited (RFC 6176), and it is not mistaken for TLS here.
		const std::vector<std::uint8_t> sslv2{0x80, 0x2E, 0x01, 0x03, 0x01};
		CHECK(classify(sslv2) == Wire::Unknown);
	}

	void neither()
	{
		CHECK(classify({}) == Wire::Unknown);  // nothing read: never a guess
		CHECK(of("get / HTTP/1.1") == Wire::Unknown);  // methods are case-sensitive
		CHECK(of(" GET / HTTP/1.1") == Wire::Unknown);
		CHECK(of("\r\nGET / HTTP/1.1") == Wire::Unknown);
		CHECK(of_octet(0x00) == Wire::Unknown);
		CHECK(of_octet(0xFF) == Wire::Unknown);
	}

	void only_the_first_octet()
	{
		// 0x16 later in a request changes nothing: only the opening octet is read.
		std::vector<std::uint8_t> request{'P', 'O', 'S', 'T', ' ', '/', ' '};
		request.push_back(0x16);
		CHECK(classify(request) == Wire::Cleartext);

		// And a 0x16 opener followed by garbage is still routed to TLS. Classification
		// routes; the TLS library is what rejects the garbage.
		const std::vector<std::uint8_t> not_tls{0x16, 0xFF, 0xFF, 0x00, 0x00};
		CHECK(classify(not_tls) == Wire::Tls);
	}

	// Usable at compile time, which is also a statement that it has no side effects.
	static_assert(classify(std::span<const std::uint8_t>{}) == Wire::Unknown);
}  // namespace

int main()
{
	every_octet();
	http_methods();
	tls_records();
	neither();
	only_the_first_octet();
	return octet_test::report("classify");
}
