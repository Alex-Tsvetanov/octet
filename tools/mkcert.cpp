// mkcert.cpp: writes a test CA and a server certificate for localhost.

#include <cstdio>

#include "octet/pki.hpp"

int main(int argc, char** argv)
{
	if (argc != 2)
	{
		std::fputs("usage: octet-mkcert DIR\n", stderr);
		return 2;
	}
	const auto files = octet::pki::make_test_pki(argv[1]);
	if (!files)
	{
		std::fprintf(stderr, "octet-mkcert: %s\n", files.error().c_str());
		return 1;
	}
	std::printf("%s\n%s\n%s\n", files->ca_cert.string().c_str(), files->server_chain.string().c_str(),
	            files->server_key.string().c_str());
	return 0;
}
