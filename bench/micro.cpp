// micro.cpp: what detection adds to a connection in memory, with the network taken out.
//
// From the code: when the first read brings the whole ClientHello (it did for every
// connection the end-to-end benchmark recorded), detection costs no extra system call.
// The dedicated listener reads the ClientHello once, into the TLS input buffer. The
// detecting listener reads it once too, into its classification buffer, and then copies
// it into the TLS input buffer through the replay reader. What remains is that copy, one
// heap allocation, one comparison of the first octet and the construction of the reader.
// This program times exactly that difference, many times over, and nothing else.
//
// A memcpy from a fixed buffer stands in for recv() on both paths, so the system call,
// which both paths make once, cancels out by construction rather than by measurement.

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "octet/classify.hpp"
#include "octet/replay.hpp"

namespace
{
	using Clock = std::chrono::steady_clock;

	constexpr std::size_t kHello = 517;      // the ClientHello size the benchmark recorded
	constexpr std::size_t kFirstRead = 2048;  // as in server.cpp
	constexpr std::size_t kTlsChunk = 16 * 1024;  // as in tls.cpp
	constexpr int kIterations = 200000;
	constexpr int kRounds = 15;

	std::array<std::uint8_t, kHello> wire_bytes()
	{
		std::array<std::uint8_t, kHello> b{};
		b[0] = 0x16;
		b[1] = 0x03;
		b[2] = 0x01;
		b[3] = static_cast<std::uint8_t>((kHello - 5) >> 8);
		b[4] = static_cast<std::uint8_t>((kHello - 5) & 0xFF);
		b[5] = 0x01;
		for (std::size_t i = 6; i < kHello; ++i)
		{
			b[i] = static_cast<std::uint8_t>(i * 31);
		}
		return b;
	}

	// The kernel side of recv(): copy what is waiting into the caller buffer.
	std::size_t fake_recv(const std::array<std::uint8_t, kHello>& wire, std::span<std::uint8_t> out)
	{
		const std::size_t n = std::min(out.size(), wire.size());
		std::memcpy(out.data(), wire.data(), n);
		return n;
	}

	// Dedicated TLS listener: the ClientHello goes straight into the TLS input buffer.
	std::uint64_t dedicated(const std::array<std::uint8_t, kHello>& wire, std::array<std::uint8_t, kTlsChunk>& tls_in)
	{
		const std::size_t n = fake_recv(wire, tls_in);
		return tls_in[n - 1] + n;
	}

	// Detecting listener: read into the classification buffer, classify, wrap it in the
	// replay reader, and let the TLS layer read it from there.
	std::uint64_t detecting(const std::array<std::uint8_t, kHello>& wire, std::array<std::uint8_t, kTlsChunk>& tls_in)
	{
		std::vector<std::uint8_t> first(kFirstRead);
		const std::size_t n = fake_recv(wire, first);
		first.resize(n);
		if (octet::classify(first) != octet::Wire::Tls)
		{
			return 0;
		}
		octet::ReplayReader reader(std::move(first), [](std::span<std::uint8_t>, const octet::Deadline&) {
			return octet::net::IoResult{octet::net::Io::Closed, 0};
		});
		const auto r = reader.read(tls_in, octet::Deadline(std::chrono::seconds(1)));
		return tls_in[r.bytes - 1] + r.bytes;
	}

	template <class F>
	double ns_per_call(F&& f, std::uint64_t& sink)
	{
		const auto t0 = Clock::now();
		for (int i = 0; i < kIterations; ++i)
		{
			sink += f();
		}
		const auto t1 = Clock::now();
		return std::chrono::duration<double, std::nano>(t1 - t0).count() / kIterations;
	}
}  // namespace

int main()
{
	const auto wire = wire_bytes();
	static std::array<std::uint8_t, kTlsChunk> tls_in{};
	std::uint64_t sink = 0;

	std::vector<double> a;
	std::vector<double> b;
	for (int round = 0; round < kRounds; ++round)
	{
		// Alternate which path goes first, so neither always runs on a warmer cache.
		if (round % 2 == 0)
		{
			a.push_back(ns_per_call([&] { return dedicated(wire, tls_in); }, sink));
			b.push_back(ns_per_call([&] { return detecting(wire, tls_in); }, sink));
		}
		else
		{
			b.push_back(ns_per_call([&] { return detecting(wire, tls_in); }, sink));
			a.push_back(ns_per_call([&] { return dedicated(wire, tls_in); }, sink));
		}
	}
	std::sort(a.begin(), a.end());
	std::sort(b.begin(), b.end());
	const double med_a = a[a.size() / 2];
	const double med_b = b[b.size() / 2];

	std::printf("rounds %d, iterations per round %d, ClientHello %zu octets\n", kRounds, kIterations, kHello);
	std::printf("dedicated  ns per connection: median %.1f, min %.1f, max %.1f\n", med_a, a.front(), a.back());
	std::printf("detecting  ns per connection: median %.1f, min %.1f, max %.1f\n", med_b, b.front(), b.back());
	std::printf("difference ns per connection: %.1f\n", med_b - med_a);
	std::printf("(checksum %llu)\n", static_cast<unsigned long long>(sink));
	return 0;
}
