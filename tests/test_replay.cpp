#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <vector>

#include "check.hpp"
#include "octet/replay.hpp"

using octet::Deadline;
using octet::ReplayReader;
using octet::net::Io;
using octet::net::IoResult;

namespace
{
	// A source that hands out a script of chunks, one per read, then end of stream.
	octet::ReadFn scripted(std::deque<std::string> chunks, int* reads = nullptr)
	{
		auto state = std::make_shared<std::deque<std::string>>(std::move(chunks));
		return [state, reads](std::span<std::uint8_t> out, const Deadline&) -> IoResult {
			if (reads != nullptr)
			{
				++*reads;
			}
			if (state->empty())
			{
				return {Io::Closed, 0};
			}
			std::string& front = state->front();
			const std::size_t n = std::min(out.size(), front.size());
			std::copy_n(front.begin(), n, out.begin());
			front.erase(0, n);
			if (front.empty())
			{
				state->pop_front();
			}
			return {Io::Ok, n};
		};
	}

	std::string drain(ReplayReader& r, std::size_t chunk)
	{
		std::string all;
		std::vector<std::uint8_t> buf(chunk);
		const Deadline d(std::chrono::seconds(1));
		for (;;)
		{
			const auto res = r.read(buf, d);
			if (res.status != Io::Ok)
			{
				return all;
			}
			all.append(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(res.bytes));
		}
	}

	void pushback_comes_first()
	{
		int reads = 0;
		ReplayReader r({'G', 'E'}, scripted({"T / HTTP/1.1\r\n"}, &reads));
		CHECK(drain(r, 64) == "GET / HTTP/1.1\r\n");
	}

	void source_untouched_while_pushback_remains()
	{
		int reads = 0;
		ReplayReader r({'a', 'b', 'c'}, scripted({"def"}, &reads));
		std::vector<std::uint8_t> two(2);
		const Deadline d(std::chrono::seconds(1));

		auto res = r.read(two, d);
		CHECK(res.status == Io::Ok && res.bytes == 2);
		CHECK(r.has_pushback());
		CHECK(reads == 0);

		res = r.read(two, d);  // one replayed octet left: a short read, not a mix
		CHECK(res.status == Io::Ok && res.bytes == 1 && two[0] == 'c');
		CHECK(!r.has_pushback());
		CHECK(reads == 0);

		res = r.read(two, d);
		CHECK(res.status == Io::Ok && reads == 1);
	}

	void dribbled_stream_survives_intact()
	{
		// The first octet was read for classification; the rest arrives one octet per
		// segment, as a TCP peer is entitled to send it.
		std::string record = "\x16\x03\x01\x00\x20";
		record.append(32, '\xAB');
		std::deque<std::string> rest;
		for (std::size_t i = 1; i < record.size(); ++i)
		{
			rest.emplace_back(1, record[i]);
		}
		ReplayReader r({static_cast<std::uint8_t>(record[0])}, scripted(std::move(rest)));
		CHECK(drain(r, 7) == record);
	}

	void empty_pushback_reads_source()
	{
		int reads = 0;
		ReplayReader r({}, scripted({"x"}, &reads));
		CHECK(!r.has_pushback());
		CHECK(drain(r, 8) == "x");
		CHECK(reads == 2);  // the byte, then end of stream
	}
}  // namespace

int main()
{
	pushback_comes_first();
	source_untouched_while_pushback_remains();
	dribbled_stream_survives_intact();
	empty_pushback_reads_source();
	return octet_test::report("replay");
}
