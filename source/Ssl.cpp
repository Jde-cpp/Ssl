﻿#include "Ssl.h"

#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/remove_whitespace.hpp>
#include <jde/Assert.h>
#define var const auto

namespace Jde
{
	string Ssl::Encode( sv url )noexcept
	{
		ostringstream os;
		std::ostream hexcout{ os.rdbuf() };
		hexcout << std::hex << std::uppercase << std::setfill('0');
		var end = url.data()+url.size();
		for( auto p=url.data(); p<end; ++p )
		{
			char ch = *p;
			if( ch>=0 )//&& ch<128
			{
				char ch = (char)*p;
				if( isalnum(*p) || ch == '-' || ch == '_' || ch == '.' || ch == '~' )
					os << ch;
				else
				{
					os << '%';
					int x = ch;
					hexcout << std::setw(2) << x;
				}
			}
			else
			{
				//%E2%89%88
				os << '%';
				unsigned char value = ch;
				hexcout << std::setw(2) << static_cast<uint>(value);
			}
		}
		return os.str();
	}

	//TODO: very bad!  https://stackoverflow.com/questions/9507184/can-openssl-on-windows-use-the-system-certificate-store
	bool Ssl::verify_certificate( bool preverified, boost::asio::ssl::verify_context& ctx )noexcept
	{
		char subject_name[256];
		X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
		X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
		//std::cout << "Verifying:  " << subject_name << std::endl;
		preverified = true;
		return preverified;
	}

	RSA* CreatePrivateRsa( string key )
	{
		BIO* keybio = BIO_new_mem_buf( (void*)key.c_str(), -1 );
		if( !keybio )
			THROW( RuntimeException("!keybio") );
		RSA* pRsa = nullptr;
		pRsa = PEM_read_bio_RSAPrivateKey( keybio, &pRsa, nullptr, nullptr );
		if( !pRsa )
		{
			char buffer[120];
			ERR_error_string( ERR_get_error(), buffer );
			THROW( RuntimeException(buffer) );
		}
		return pRsa;
	}

	bool RSASign( RSA* rsa, const unsigned char* Msg, size_t MsgLen, unsigned char** EncMsg,  size_t* MsgLenEnc )
	{
		EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
		EVP_PKEY* priKey  = EVP_PKEY_new(); //free?
		EVP_PKEY_assign_RSA(priKey, rsa);
		if( EVP_DigestSignInit(m_RSASignCtx,nullptr, EVP_sha1(), nullptr,priKey)<=0 )
			return false;
		if( EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0 )
			return false;
		if( EVP_DigestSignFinal(m_RSASignCtx, nullptr, MsgLenEnc) <=0 )
			return false;

		*EncMsg = (unsigned char*)malloc(*MsgLenEnc);
		if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0)
			return false;

		EVP_MD_CTX_reset( m_RSASignCtx );
		return true;
	}
	//https://stackoverflow.com/questions/7053538/how-do-i-encode-a-string-to-base64-using-only-boost
	std::string Ssl::Encode64( const std::string &val )
	{
		using namespace boost::archive::iterators;
		using It = base64_from_binary<transform_width<std::string::const_iterator, 6, 8>>;
		auto tmp = std::string( It(std::begin(val)), It(std::end(val)) );
		return tmp.append( (3 - val.size() % 3) % 3, '=' );
	}

	string Ssl::RsaSign( sv value, sv key )
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

	std::string Ssl::Decode64( const std::string& s )noexcept(false) //https://stackoverflow.com/questions/10521581/base64-encode-using-boost-throw-exception
	{
		namespace bai = boost::archive::iterators; typedef bai::transform_width< bai::binary_from_base64<bai::remove_whitespace<std::string::const_iterator> >, 8, 6 > IT;
		return std::string{ IT(s.begin()), IT(s.end()) };
	}

	auto RsaDeleter=[](RSA* p){ RSA_free(p); };
	auto PKeyDeleter=[](EVP_PKEY* p){ EVP_PKEY_free(p); };

	//https://stackoverflow.com/questions/28770426/rsa-public-key-conversion-with-just-modulus
	unique_ptr<EVP_PKEY,decltype(PKeyDeleter)> RsaPemFromModExp( const string& modulus, const string& exponent )noexcept(false)
	{
		BIGNUM* pMod = BN_bin2bn( (const unsigned char *)modulus.c_str(), (int)modulus.size(), nullptr ); THROW_IF( !pMod, "BN_bin2bn"sv );
		BIGNUM *pExp = BN_bin2bn( (const unsigned char *)exponent.c_str(), (int)exponent.size(), nullptr ); THROW_IF( !pMod, "BN_bin2bn({})"sv, exponent );
		unique_ptr<RSA,decltype(RsaDeleter)> pRsa{ RSA_new(), RsaDeleter };
		RSA_set0_key( pRsa.get(), pMod, pExp, nullptr );

		unique_ptr<EVP_PKEY,decltype(PKeyDeleter)> pKey{ EVP_PKEY_new(), PKeyDeleter };
		int rc = EVP_PKEY_set1_RSA(pKey.get(), pRsa.get()); ASSERT(rc == 1);
		return pKey;
	}

	void rsatest();
	void Ssl::Verify( const string& modulus, const string& exponent, const string& decrypted, const string& signature )noexcept(false)
	{
		rsatest();
    	auto pCtx = EVP_MD_CTX_create();
    	var pMd = EVP_get_digestbyname( "SHA256" ); THROW_IF( !pMd, Exception("EVP_get_digestbyname({})", "SHA256") ); //"SHA256"
		EVP_VerifyInit_ex( pCtx, pMd, nullptr );
		EVP_VerifyUpdate( pCtx, decrypted.c_str(), decrypted.size() );
		var pKey = RsaPemFromModExp( modulus, exponent );
		std::string decodedSignature = Encode64( signature );
		var result = EVP_VerifyFinal( pCtx, (const unsigned char *)decodedSignature.c_str(), (int)decodedSignature.size(), pKey.get() );
		THROW_IF( result!=1, CodeException("Ssl::Verify - failed", {result, std::generic_category()} ) );
	}

	void rsatest()
	{
		const EVP_MD *sha256 = EVP_get_digestbyname("sha256");

		if(!sha256){
		fprintf(stderr,"SHA256 not available\n");
		return;
		}

		printf("Now try signing with X.509 certificates and EVP\n");

		char ptext[16];
		memset(ptext,0,sizeof(ptext));
		strcpy(ptext,"Simson");

		unsigned char sig[1024]={0};
		uint32_t  siglen = sizeof(sig);

		BIO *bp = BIO_new_file( "../signing_key.pem", "r" );

		auto pCtx = EVP_MD_CTX_create();
		//EVP_MD_CTX md;
		EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bp,0,0,0);

		EVP_SignInit(pCtx,sha256);
		EVP_SignUpdate(pCtx,ptext,sizeof(ptext));
		EVP_SignFinal(pCtx,sig,&siglen,pkey);

		/* let's try to verify it */
		BIO* bp2 = BIO_new_file( "../signing_key.pub", "r" );
		X509 *x = 0;
		PEM_read_bio_X509( bp2,&x,0,0 );
		EVP_PKEY *pubkey = X509_get_pubkey(x);

		printf("pubkey=%p\n",pubkey);

		EVP_VerifyInit(pCtx,sha256);
		EVP_VerifyUpdate(pCtx,ptext,sizeof(ptext));
		int r = EVP_VerifyFinal(pCtx,sig,siglen,pubkey);
		printf("r=%d\n",r);

		printf("do it again...\n");
		EVP_VerifyInit(pCtx,sha256);
		EVP_VerifyUpdate(pCtx,ptext,sizeof(ptext));
		r = EVP_VerifyFinal(pCtx,sig,siglen,pubkey);
		printf("r=%d\n",r);

		printf("make a tiny change...\n");
		ptext[0]='f';
		EVP_VerifyInit(pCtx,sha256);
		EVP_VerifyUpdate(pCtx,ptext,sizeof(ptext));
		r = EVP_VerifyFinal(pCtx,sig,siglen,pubkey);
		printf("r=%d\n",r);
	}

	string Ssl::SendEmpty( sv host, sv target, sv authorization, http::verb verb )noexcept(false)
	{
		http::request<http::empty_body> req{ verb, string(target), 11 };
		SetRequest( req, host, "application/x-www-form-urlencoded"sv, authorization );
		return Send( req, host, target );
	}

}