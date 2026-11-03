// check.hpp: the whole test framework. A failed CHECK prints and counts; it never stops.

#pragma once

#include <cstdio>

namespace octet_test
{
	inline int& failures()
	{
		static int count = 0;
		return count;
	}

	inline int& checks()
	{
		static int count = 0;
		return count;
	}

	inline void check(bool ok, const char* expr, const char* file, int line)
	{
		++checks();
		if (!ok)
		{
			++failures();
			std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, expr);
		}
	}

	inline int report(const char* suite)
	{
		std::printf("%s: %d checks, %d failed\n", suite, checks(), failures());
		return failures() == 0 ? 0 : 1;
	}
}  // namespace octet_test

#define CHECK(expr) ::octet_test::check(static_cast<bool>(expr), #expr, __FILE__, __LINE__)
