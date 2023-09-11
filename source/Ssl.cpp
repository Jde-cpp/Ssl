#include "Ssl.h"

#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

//#include <boost/algorithm/hex.hpp>
#include <jde/Assert.h>
#define var const auto

namespace Jde
{
	static const LogTag& _logLevel = Logging::TagLevel( "net" );
	α Ssl::NetLevel()ι->const LogTag&{ return _logLevel; }

	α Ssl::DecodeUri( sv x )ι->string
	{
		auto from_hex = [](char ch) { return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10; };
		string y{}; y.reserve( x.size() );
    for (auto i = x.begin(), n = x.end(); i != n; ++i)
		{
			char ch = *i;
      if( ch == '%' )
			{
        if (i[1] && i[2])
				{
          ch = from_hex(i[1]) << 4 | from_hex(i[2]);
          i += 2;
        }
      }
			else if (ch == '+')
        ch = ' ';
			y+=ch;
		}
		return y;
	}

	//TODO: very bad!  https://stackoverflow.com/questions/9507184/can-openssl-on-windows-use-the-system-certificate-store
	α Ssl::verify_certificate( bool preverified, boost::asio::ssl::verify_context& ctx )ι->bool
	{
		char subject_name[256];
		X509* cert = X509_STORE_CTX_get_current_cert( ctx.native_handle() );
		X509_NAME_oneline( X509_get_subject_name(cert), subject_name, 256 );
		preverified = true;
		return preverified;
	}

	α CreatePrivateRsa( string key )->RSA*
	{
		BIO* keybio = BIO_new_mem_buf( (void*)key.c_str(), -1 ); THROW_IF( !keybio, "!keybio" );
		RSA* pRsa = nullptr;
		pRsa = PEM_read_bio_RSAPrivateKey( keybio, &pRsa, nullptr, nullptr );
		if( !pRsa )
		{
			char buffer[120];
			ERR_error_string( ERR_get_error(), buffer );
			THROW( buffer );
		}
		return pRsa;
	}

	α Ssl::RsaSign( sv value, sv key )->string
	{
		auto p = HMAC_CTX_new();
		HMAC_Init_ex( p, (void*)key.data(), (int)key.size(), EVP_sha1(), nullptr );
		HMAC_Update( p, (const unsigned char*)value.data(), value.size() );
		unsigned length = 2048;
		unsigned char buffer[2048];
		HMAC_Final( p, buffer, &length );
		HMAC_CTX_free( p );
		return Encode64( string(buffer, buffer+length) );
	}

	using RsaPtr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
	using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;

	//https://stackoverflow.com/questions/28770426/rsa-public-key-conversion-with-just-modulus
	α RsaPemFromModExp( const vector<unsigned char>& modulus, const vector<unsigned char>& exponent )ε->KeyPtr
	{
		BIGNUM* pMod = BN_bin2bn( modulus.data(), (int)modulus.size(), nullptr ); THROW_IF( !pMod, "BN_bin2bn"sv );

		BIGNUM *pExp = BN_bin2bn( exponent.data(), (int)exponent.size(), nullptr ); THROW_IF( !pMod, "BN_bin2bn({})"sv, Ssl::Encode64(exponent) );
		RsaPtr pRsa{ RSA_new(), ::RSA_free };

		CHECK( RSA_set0_key(pRsa.get(), pMod, pExp, nullptr)==1 );
		KeyPtr pKey{ EVP_PKEY_new(), ::EVP_PKEY_free };
		CHECK( EVP_PKEY_set1_RSA(pKey.get(), pRsa.get())==1 );
		return pKey;
	}

	α rsatest()->void;
	α Ssl::Verify( const vector<unsigned char>& modulus, const vector<unsigned char>& exponent, str decrypted, str signature )ε->void
	{
    	auto pCtx = EVP_MD_CTX_create();
    	var pMd = EVP_get_digestbyname( "SHA256" ); THROW_IF( !pMd, "EVP_get_digestbyname({})", "SHA256" ); //"SHA256"
		THROW_IF( EVP_VerifyInit_ex( pCtx, pMd, nullptr )!=1, "EVP_VerifyInit_ex failed" );
		THROW_IF( EVP_VerifyUpdate( pCtx, decrypted.c_str(), decrypted.size())!=1, "EVP_VerifyUpdate failed" );
		var pKey = RsaPemFromModExp( modulus, exponent );
		var result = EVP_VerifyFinal( pCtx, (const unsigned char*)signature.c_str(), (int)signature.size(), pKey.get() );

		THROW_IF( result!=1, "EVP_VerifyFinal failed {}", ERR_error_string(ERR_get_error(), nullptr) );
	}

	α Ssl::SendEmpty( sv host, sv target, sv authorization, http::verb verb )ε->string
	{
		http::request<http::empty_body> req{ verb, string(target), 11 };
		SetRequest( req, host, "application/x-www-form-urlencoded"sv, authorization );
		return Send( req, host, target );
	}

}