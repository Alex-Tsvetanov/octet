// deadline.hpp: one absolute point in time that several waits share.
//
// A relative timeout restarts on every call, so a peer that sends one byte just before
// each timeout keeps a connection open for ever. An absolute deadline cannot be extended
// by the peer: every wait computes what is left of the same budget.

#pragma once

#include <algorithm>
#include <chrono>

namespace octet
{

	using Clock = std::chrono::steady_clock;

	class Deadline
	{
	public:
		explicit Deadline(Clock::duration budget) : at_(Clock::now() + budget) {}
		explicit Deadline(Clock::time_point at) : at_(at) {}

		[[nodiscard]] bool expired() const noexcept { return Clock::now() >= at_; }

		// Milliseconds left, rounded up so that a wait never returns early, and clamped
		// to zero once the deadline has passed.
		[[nodiscard]] int remaining_ms() const noexcept
		{
			const auto left = at_ - Clock::now();
			if (left <= Clock::duration::zero())
			{
				return 0;
			}
			const auto ms = std::chrono::ceil<std::chrono::milliseconds>(left).count();
			return static_cast<int>(std::min<long long>(ms, 24LL * 60 * 60 * 1000));
		}

		[[nodiscard]] Clock::time_point at() const noexcept { return at_; }

	private:
		Clock::time_point at_;
	};

}  // namespace octet
