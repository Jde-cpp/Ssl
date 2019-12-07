#include "Ssl.h"
#include <iomanip>
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
//#include "../io/File.h"

#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>

#define var const auto

namespace Jde
{
	string Ssl::Encode( string_view url )noexcept
	{
		ostringstream os;
		std::ostream hexcout{ os.rdbuf() };
		hexcout << std::hex << std::uppercase << std::setfill('0');
		//uint x2=10;
		//hexcout << "[" << x2 << "]";
		var end = url.data()+url.size();
		for( auto p=url.data(); p<end; ++p )
		{
			char ch = *p;
			//char16_t compare = 128U;
			if( ch>=0 )//&& ch<128
			{
				char ch = (char)*p;
				if( isalnum(*p) || ch == '-' || ch == '_' || ch == '.' || ch == '~' ) 
					os << ch;
				else
				{
					os << '%';
					int x = ch;
					// if( x<16 )
					// 	hexcout << "0";
					hexcout << std::setw(2) << x;
				}
			}				
			else 
			{
				//%E2%89%88
				os << '%';
				unsigned char value = ch;
				char16_t value2 = value;
				hexcout << std::setw(2) << value2;
				//DBG0( os.str() );
				// std::wstring_convert<std::codecvt_utf8<wchar_t>> utf8_conv;
				// var bytes = utf8_conv.to_bytes( wch );
				// for( var byte : bytes )
				// {
				// 	os << '%';
				// 	uint8_t value = byte;
				// 	// if( value<16 )
				// 	// 	hexcout << "0";
				// 	hexcout << std::setw(2) << (uint16_t)value;//https://stackoverflow.com/questions/1532640/which-iomanip-manipulators-are-sticky
				// }
			}
			//hexcout << "[" << x2 << "]";
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
		EVP_PKEY* priKey  = EVP_PKEY_new();
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

	string Ssl::RsaSign( std::string_view value, std::string_view key )
	{
		auto p = HMAC_CTX_new();
		HMAC_Init_ex( p, (void*)key.data(), (int)key.size(), EVP_sha1(), nullptr );
		HMAC_Update( p, (const unsigned char*)value.data(), value.size() );
		unsigned length = 2048;
		unsigned char buffer[2048];
		HMAC_Final( p, buffer, &length );
		HMAC_CTX_free( p );
		return Encode64( string(buffer, buffer+length) );
		//84 2B 52 99 88 7E 88 7602 12 A0 56 AC 4E C2 EE 16 26 B5 49
		//84 e8 49 83 33 cc a5 9b 57 1c 24 de 96 e2 12 d5 57 47 50 7f
		//return true;
	}
}