// replay.hpp: give back the bytes that classification already read.
//
// Deciding the protocol means reading at least one octet from the socket. That octet is
// also the first octet of the ClientHello or of the request line, and the layer that
// parses those needs it. There are two ways to keep it. MSG_PEEK leaves it in the kernel,
// at the cost of a second system call that reads it again. Reading it for real and
// handing it on costs nothing in the kernel; the next layer just reads this buffer before
// it reads the socket. ReplayReader is the second way.

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <span>
#include <utility>
#include <vector>

#include "octet/deadline.hpp"
#include "octet/net.hpp"

namespace octet
{

	// Anything bytes can be read from: a socket, a TLS session, a scripted test source.
	using ReadFn = std::function<net::IoResult(std::span<std::uint8_t>, const Deadline&)>;

	class ReplayReader
	{
	public:
		ReplayReader(std::vector<std::uint8_t> pushback, ReadFn source)
		    : pushback_(std::move(pushback)), source_(std::move(source))
		{
		}

		// Returns replayed bytes first. Only once they are gone does it touch the source,
		// so a caller can never see the stream out of order or with a gap.
		net::IoResult read(std::span<std::uint8_t> out, const Deadline& deadline)
		{
			if (pos_ < pushback_.size())
			{
				const std::size_t n = std::min(out.size(), pushback_.size() - pos_);
				std::memcpy(out.data(), pushback_.data() + pos_, n);
				pos_ += n;
				return {net::Io::Ok, n};
			}
			return source_(out, deadline);
		}

		[[nodiscard]] bool has_pushback() const noexcept { return pos_ < pushback_.size(); }

	private:
		std::vector<std::uint8_t> pushback_;
		std::size_t pos_ = 0;
		ReadFn source_;
	};

}  // namespace octet
