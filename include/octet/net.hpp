// net.hpp: the part of the socket API that differs between Winsock and POSIX, behind one
// interface. Everything above this file is platform independent.

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>

#include "octet/deadline.hpp"

namespace octet::net
{

#ifdef _WIN32
	using native_handle = std::uintptr_t;  // SOCKET
#else
	using native_handle = int;
#endif

	// Initialises Winsock on Windows; does nothing elsewhere. One instance per process.
	class Runtime
	{
	public:
		Runtime();
		~Runtime();
		Runtime(const Runtime&) = delete;
		Runtime& operator=(const Runtime&) = delete;
	};

	enum class Io : std::uint8_t
	{
		Ok,       // at least one byte moved
		Closed,   // orderly end of stream from the peer
		Timeout,  // the deadline passed first
		Error     // reset, or any other socket error
	};

	struct IoResult
	{
		Io status = Io::Error;
		std::size_t bytes = 0;
	};

	// Move-only owner of one socket. The destructor closes it.
	class Socket
	{
	public:
		Socket() noexcept;
		explicit Socket(native_handle h) noexcept;
		~Socket();
		Socket(Socket&& other) noexcept;
		Socket& operator=(Socket&& other) noexcept;
		Socket(const Socket&) = delete;
		Socket& operator=(const Socket&) = delete;

		[[nodiscard]] bool valid() const noexcept;
		[[nodiscard]] native_handle handle() const noexcept { return h_; }
		void close() noexcept;

		// Half-close: no more writes from this side. The peer reads end of stream.
		void shutdown_write() noexcept;

	private:
		native_handle h_;
	};

	// A listening TCP socket on host:port. Port 0 asks the system for a free port.
	std::expected<Socket, std::string> listen_tcp(const std::string& host, std::uint16_t port, int backlog);

	// The port a bound socket actually got.
	std::uint16_t local_port(const Socket& s);

	// Blocks until a connection arrives.
	std::expected<Socket, std::string> accept(const Socket& listener);

	// Waits until data is readable or the deadline passes, then reads once.
	IoResult recv_some(const Socket& s, std::span<std::uint8_t> out, const Deadline& deadline);

	// Writes every byte or reports why it could not.
	Io send_all(const Socket& s, std::span<const std::uint8_t> in, const Deadline& deadline);

	// The last socket error as text, for logs.
	std::string last_error();

}  // namespace octet::net
