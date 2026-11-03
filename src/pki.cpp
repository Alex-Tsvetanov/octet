#include "octet/pki.hpp"

#include <memory>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace octet::pki
{

	namespace
	{
		struct Free
		{
			void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
			void operator()(X509* p) const { X509_free(p); }
			void operator()(X509_EXTENSION* p) const { X509_EXTENSION_free(p); }
			void operator()(BIO* p) const { BIO_free_all(p); }
		};
		template <class T>
		using Owned = std::unique_ptr<T, Free>;

		constexpr long kValiditySeconds = 30L * 24 * 60 * 60;

		std::string openssl_error(const char* what)
		{
			char text[256] = {};
			ERR_error_string_n(ERR_get_error(), text, sizeof text);
			ERR_clear_error();
			return std::string(what) + ": " + text;
		}

		bool add_ext(X509* cert, X509* issuer, int nid, const char* value)
		{
			X509V3_CTX ctx;
			X509V3_set_ctx_nodb(&ctx);
			X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
			Owned<X509_EXTENSION> ext(X509V3_EXT_conf_nid(nullptr, &ctx, nid, value));
			return ext && X509_add_ext(cert, ext.get(), -1) == 1;
		}

		bool random_serial(X509* cert)
		{
			BIGNUM* bn = BN_new();
			const bool ok = bn != nullptr && BN_rand(bn, 64, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) == 1 &&
			                BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(cert)) != nullptr;
			BN_free(bn);
			return ok;
		}

		// A certificate for `key`, named `cn`, signed by `signer` with `signer_key`. When
		// `signer` is null the certificate signs itself (the CA case).
		Owned<X509> make_cert(EVP_PKEY* key, const char* cn, X509* signer, EVP_PKEY* signer_key, bool is_ca)
		{
			Owned<X509> cert(X509_new());
			if (!cert || X509_set_version(cert.get(), 2) != 1 || !random_serial(cert.get()))
			{
				return nullptr;
			}
			X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60);
			X509_gmtime_adj(X509_getm_notAfter(cert.get()), kValiditySeconds);
			X509_set_pubkey(cert.get(), key);

			X509_NAME* name = X509_get_subject_name(cert.get());
			X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("octet test"),
			                           -1, -1, 0);
			X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(cn), -1, -1, 0);

			X509* issuer = signer != nullptr ? signer : cert.get();
			X509_set_issuer_name(cert.get(), X509_get_subject_name(issuer));

			const bool ok =
			    is_ca ? add_ext(cert.get(), issuer, NID_basic_constraints, "critical,CA:TRUE,pathlen:0") &&
			                add_ext(cert.get(), issuer, NID_key_usage, "critical,keyCertSign,cRLSign") &&
			                add_ext(cert.get(), issuer, NID_subject_key_identifier, "hash")
			          : add_ext(cert.get(), issuer, NID_basic_constraints, "critical,CA:FALSE") &&
			                add_ext(cert.get(), issuer, NID_key_usage, "critical,digitalSignature") &&
			                add_ext(cert.get(), issuer, NID_ext_key_usage, "serverAuth") &&
			                add_ext(cert.get(), issuer, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1") &&
			                add_ext(cert.get(), issuer, NID_subject_key_identifier, "hash") &&
			                add_ext(cert.get(), issuer, NID_authority_key_identifier, "keyid:always");
			if (!ok)
			{
				return nullptr;
			}
			if (X509_sign(cert.get(), signer_key != nullptr ? signer_key : key, EVP_sha256()) <= 0)
			{
				return nullptr;
			}
			return cert;
		}

		bool write_pem(const std::filesystem::path& path, X509* first, X509* second, EVP_PKEY* key)
		{
			Owned<BIO> out(BIO_new_file(path.string().c_str(), "wb"));
			if (!out)
			{
				return false;
			}
			if (first != nullptr && PEM_write_bio_X509(out.get(), first) != 1)
			{
				return false;
			}
			if (second != nullptr && PEM_write_bio_X509(out.get(), second) != 1)
			{
				return false;
			}
			if (key != nullptr && PEM_write_bio_PrivateKey(out.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1)
			{
				return false;
			}
			return true;
		}
	}  // namespace

	std::expected<Files, std::string> make_test_pki(const std::filesystem::path& dir)
	{
		std::error_code ec;
		std::filesystem::create_directories(dir, ec);
		if (ec)
		{
			return std::unexpected("create " + dir.string() + ": " + ec.message());
		}

		Owned<EVP_PKEY> ca_key(EVP_EC_gen("P-256"));
		Owned<EVP_PKEY> server_key(EVP_EC_gen("P-256"));
		if (!ca_key || !server_key)
		{
			return std::unexpected(openssl_error("key generation"));
		}

		Owned<X509> ca = make_cert(ca_key.get(), "octet test CA", nullptr, nullptr, true);
		if (!ca)
		{
			return std::unexpected(openssl_error("CA certificate"));
		}
		Owned<X509> server = make_cert(server_key.get(), "localhost", ca.get(), ca_key.get(), false);
		if (!server)
		{
			return std::unexpected(openssl_error("server certificate"));
		}

		Files files{dir / "ca.pem", dir / "server.pem", dir / "server.key"};
		if (!write_pem(files.ca_cert, ca.get(), nullptr, nullptr) ||
		    !write_pem(files.server_chain, server.get(), ca.get(), nullptr) ||
		    !write_pem(files.server_key, nullptr, nullptr, server_key.get()))
		{
			return std::unexpected(openssl_error("write PEM"));
		}
		return files;
	}

}  // namespace octet::pki
