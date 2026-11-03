// pki.hpp: a throwaway certificate authority and server certificate for tests and demos.
//
// Two levels on purpose. A self-signed server certificate would make the client trust the
// server key directly, which is not how the web works. Here the client trusts a CA, and
// the server proves its name with a certificate that CA signed: the chain a browser checks.

#pragma once

#include <expected>
#include <filesystem>
#include <string>

namespace octet::pki
{

	struct Files
	{
		std::filesystem::path ca_cert;       // trust anchor for clients
		std::filesystem::path server_chain;  // server certificate, then the CA certificate
		std::filesystem::path server_key;    // private key of the server certificate
	};

	// Writes ca.pem, server.pem and server.key into `dir`. Keys are ECDSA P-256. The server
	// certificate names localhost and 127.0.0.1 and is valid for 30 days.
	std::expected<Files, std::string> make_test_pki(const std::filesystem::path& dir);

}  // namespace octet::pki
