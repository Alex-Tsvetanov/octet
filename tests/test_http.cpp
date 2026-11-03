#include <algorithm>
#include <memory>
#include <string>

#include "check.hpp"
#include "octet/http.hpp"

using octet::Deadline;
using octet::ReplayReader;
using octet::http::Error;
using octet::http::parse_head;
using octet::http::read_request;
using octet::net::Io;
using octet::net::IoResult;

namespace
{
	octet::ReadFn one_octet_at_a_time(std::string text, Io at_end = Io::Closed)
	{
		auto state = std::make_shared<std::string>(std::move(text));
		return [state, at_end](std::span<std::uint8_t> out, const Deadline&) -> IoResult {
			if (state->empty())
			{
				return {at_end, 0};
			}
			out[0] = static_cast<std::uint8_t>(state->front());
			state->erase(0, 1);
			return {Io::Ok, 1};
		};
	}

	void valid_heads()
	{
		const auto r = parse_head("GET /index.html HTTP/1.1\r\nHost: example\r\nAccept: */*");
		CHECK(r.has_value());
		CHECK(r && r->method == "GET" && r->target == "/index.html" && r->version == "HTTP/1.1");
		CHECK(parse_head("POST / HTTP/1.0").has_value());
	}

	void rejected_heads()
	{
		CHECK(parse_head("get / HTTP/1.1").error() == Error::BadRequest);       // lower-case method
		CHECK(parse_head("GET index HTTP/1.1").error() == Error::BadRequest);   // not origin form
		CHECK(parse_head("GET / HTTP/2.0").error() == Error::BadRequest);       // not HTTP/1.x
		CHECK(parse_head("GET  / HTTP/1.1").error() == Error::BadRequest);      // two spaces
		CHECK(parse_head("GET / HTTP/1.1 x").error() == Error::BadRequest);     // trailing word
		CHECK(parse_head("GET /a\x7f HTTP/1.1").error() == Error::BadRequest);  // control octet
		CHECK(parse_head("ABCDEFGHIJKLMNOPQ / HTTP/1.1").error() == Error::BadRequest);  // method too long
		CHECK(parse_head("GET / HTTP/1.1\r\n folded").error() == Error::BadRequest);     // obs-fold
		CHECK(parse_head("GET / HTTP/1.1\r\nHost : x").error() == Error::BadRequest);    // space before colon
		CHECK(parse_head("GET / HTTP/1.1\r\nnocolon").error() == Error::BadRequest);
	}

	void head_split_across_reads()
	{
		ReplayReader in({'G'}, one_octet_at_a_time("ET / HTTP/1.1\r\nHost: x\r\n\r\n"));
		const auto r = read_request(in, Deadline(std::chrono::seconds(1)));
		CHECK(r.has_value() && r->method == "GET");
	}

	void oversized_head()
	{
		std::string big = "GET / HTTP/1.1\r\nX: ";
		big.append(octet::http::kMaxHead + 10, 'a');
		big += "\r\n\r\n";
		ReplayReader in({}, one_octet_at_a_time(big));
		CHECK(read_request(in, Deadline(std::chrono::seconds(5))).error() == Error::TooLarge);

		// The same head in large chunks, as the network usually delivers it. The read
		// that crosses the limit also carries the blank line; the limit must still hold.
		// This is the case an earlier version of read_request got wrong.
		auto whole = std::make_shared<std::string>(big);
		ReplayReader chunked({}, [whole](std::span<std::uint8_t> out, const Deadline&) -> IoResult {
			if (whole->empty())
			{
				return {Io::Closed, 0};
			}
			const std::size_t n = std::min(out.size(), whole->size());
			std::copy_n(whole->begin(), n, out.begin());
			whole->erase(0, n);
			return {Io::Ok, n};
		});
		CHECK(read_request(chunked, Deadline(std::chrono::seconds(5))).error() == Error::TooLarge);
	}

	void peer_stops_early()
	{
		ReplayReader closed({}, one_octet_at_a_time("GET / HTTP/1.1\r\n", Io::Closed));
		CHECK(read_request(closed, Deadline(std::chrono::seconds(1))).error() == Error::Closed);

		ReplayReader silent({}, one_octet_at_a_time("GET / HTTP/1.1\r\n", Io::Timeout));
		CHECK(read_request(silent, Deadline(std::chrono::seconds(1))).error() == Error::Timeout);
	}

	void responses()
	{
		const auto r = octet::http::make_response(200, "OK", "hi\n");
		CHECK(r == "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 3\r\n"
		           "Connection: close\r\n\r\nhi\n");
		CHECK(octet::http::status_of(Error::TooLarge) == 431);
		CHECK(octet::http::status_of(Error::BadRequest) == 400);
		CHECK(octet::http::status_of(Error::Timeout) == 0);
	}
}  // namespace

int main()
{
	valid_heads();
	rejected_heads();
	head_split_across_reads();
	oversized_head();
	peer_stops_early();
	responses();
	return octet_test::report("http");
}
