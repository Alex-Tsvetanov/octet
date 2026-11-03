#include "octet/net.hpp"

#include <cstring>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace octet::net
{

	namespace
	{
#ifdef _WIN32
		using os_socket = SOCKET;
#else
		using os_socket = int;
#endif

		// The handle as the type the system calls take.
		os_socket os(native_handle h) noexcept { return static_cast<os_socket>(h); }

#ifdef _WIN32
		constexpr native_handle kInvalid = static_cast<native_handle>(INVALID_SOCKET);

		int poll_one(native_handle h, short events, int timeout_ms)
		{
			WSAPOLLFD p{};
			p.fd = static_cast<SOCKET>(h);
			p.events = events;
			return WSAPoll(&p, 1, timeout_ms);
		}

		void close_native(native_handle h) { ::closesocket(static_cast<SOCKET>(h)); }

		bool interrupted() { return false; }
#else
		constexpr native_handle kInvalid = -1;

		int poll_one(native_handle h, short events, int timeout_ms)
		{
			pollfd p{};
			p.fd = h;
			p.events = events;
			return ::poll(&p, 1, timeout_ms);
		}

		void close_native(native_handle h) { ::close(h); }

		bool interrupted() { return errno == EINTR; }
#endif

#if defined(MSG_NOSIGNAL)
		constexpr int kSendFlags = MSG_NOSIGNAL;  // Linux: no SIGPIPE on a reset peer
#else
		constexpr int kSendFlags = 0;
#endif

		void configure_accepted(native_handle h)
		{
			// Responses here are one small write each; Nagle would hold the last segment
			// back waiting for an acknowledgement and add delay that is not ours.
			int one = 1;
			::setsockopt(os(h), IPPROTO_TCP, TCP_NODELAY,
			             reinterpret_cast<const char*>(&one), sizeof one);
#if defined(SO_NOSIGPIPE)
			::setsockopt(h, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);  // macOS
#endif
		}
	}  // namespace

	Runtime::Runtime()
	{
#ifdef _WIN32
		WSADATA data{};
		::WSAStartup(MAKEWORD(2, 2), &data);
#endif
	}

	Runtime::~Runtime()
	{
#ifdef _WIN32
		::WSACleanup();
#endif
	}

	Socket::Socket() noexcept : h_(kInvalid) {}
	Socket::Socket(native_handle h) noexcept : h_(h) {}
	Socket::~Socket() { close(); }

	Socket::Socket(Socket&& other) noexcept : h_(std::exchange(other.h_, kInvalid)) {}

	Socket& Socket::operator=(Socket&& other) noexcept
	{
		if (this != &other)
		{
			close();
			h_ = std::exchange(other.h_, kInvalid);
		}
		return *this;
	}

	bool Socket::valid() const noexcept { return h_ != kInvalid; }

	void Socket::close() noexcept
	{
		if (valid())
		{
			close_native(h_);
			h_ = kInvalid;
		}
	}

	void Socket::shutdown_write() noexcept
	{
		if (valid())
		{
#ifdef _WIN32
			::shutdown(static_cast<SOCKET>(h_), SD_SEND);
#else
			::shutdown(h_, SHUT_WR);
#endif
		}
	}

	std::string last_error()
	{
#ifdef _WIN32
		return "winsock error " + std::to_string(::WSAGetLastError());
#else
		return std::strerror(errno);
#endif
	}

	std::expected<Socket, std::string> listen_tcp(const std::string& host, std::uint16_t port, int backlog)
	{
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1)
		{
			return std::unexpected("not an IPv4 address: " + host);
		}

		Socket s(static_cast<native_handle>(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)));
		if (!s.valid())
		{
			return std::unexpected("socket: " + last_error());
		}

#ifdef _WIN32
		// Without this a second server can bind the same port on Windows and steal
		// connections, which would make every test here meaningless.
		int exclusive = 1;
		::setsockopt(static_cast<SOCKET>(s.handle()), SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
		             reinterpret_cast<const char*>(&exclusive), sizeof exclusive);
#else
		int reuse = 1;
		::setsockopt(s.handle(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse);
#endif

		if (::bind(os(s.handle()), reinterpret_cast<const sockaddr*>(&addr),
		           sizeof addr) != 0)
		{
			return std::unexpected("bind: " + last_error());
		}
		if (::listen(os(s.handle()), backlog) != 0)
		{
			return std::unexpected("listen: " + last_error());
		}
		return s;
	}

	std::uint16_t local_port(const Socket& s)
	{
		sockaddr_in addr{};
		socklen_t len = sizeof addr;
		if (::getsockname(os(s.handle()), reinterpret_cast<sockaddr*>(&addr),
		                  &len) != 0)
		{
			return 0;
		}
		return ntohs(addr.sin_port);
	}

	std::expected<Socket, std::string> accept(const Socket& listener)
	{
		for (;;)
		{
			const auto h = ::accept(os(listener.handle()), nullptr, nullptr);
			if (static_cast<native_handle>(h) != kInvalid)
			{
				configure_accepted(static_cast<native_handle>(h));
				return Socket(static_cast<native_handle>(h));
			}
			if (!interrupted())
			{
				return std::unexpected("accept: " + last_error());
			}
		}
	}

	IoResult recv_some(const Socket& s, std::span<std::uint8_t> out, const Deadline& deadline)
	{
		if (out.empty())
		{
			return {Io::Ok, 0};
		}
		for (;;)
		{
			const int ready = poll_one(s.handle(), POLLIN, deadline.remaining_ms());
			if (ready == 0)
			{
				return {Io::Timeout, 0};
			}
			if (ready < 0)
			{
				if (interrupted())
				{
					continue;
				}
				return {Io::Error, 0};
			}

			const int len = static_cast<int>(out.size() > 1 << 20 ? 1 << 20 : out.size());
			const auto n = ::recv(os(s.handle()),
			                      reinterpret_cast<char*>(out.data()), len, 0);
			if (n > 0)
			{
				return {Io::Ok, static_cast<std::size_t>(n)};
			}
			if (n == 0)
			{
				return {Io::Closed, 0};
			}
			if (interrupted())
			{
				continue;
			}
			return {Io::Error, 0};
		}
	}

	Io send_all(const Socket& s, std::span<const std::uint8_t> in, const Deadline& deadline)
	{
		while (!in.empty())
		{
			const int ready = poll_one(s.handle(), POLLOUT, deadline.remaining_ms());
			if (ready == 0)
			{
				return Io::Timeout;
			}
			if (ready < 0)
			{
				if (interrupted())
				{
					continue;
				}
				return Io::Error;
			}

			const int len = static_cast<int>(in.size() > 1 << 20 ? 1 << 20 : in.size());
			const auto n = ::send(os(s.handle()),
			                      reinterpret_cast<const char*>(in.data()), len, kSendFlags);
			if (n > 0)
			{
				in = in.subspan(static_cast<std::size_t>(n));
				continue;
			}
			if (n < 0 && interrupted())
			{
				continue;
			}
			return Io::Error;
		}
		return Io::Ok;
	}

}  // namespace octet::net
