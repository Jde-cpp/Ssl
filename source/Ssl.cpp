#include "Ssl.h"

// #include <openssl/engine.h>
// #include <openssl/hmac.h>
// #include <openssl/err.h>
// #include <openssl/evp.h>
// #include <openssl/rsa.h>

//#include <boost/algorithm/hex.hpp>
//#include <jde/Assert.h>
#define var const auto

namespace Jde
{
	static sp<Jde::LogTag> _logTag{ Logging::Tag( "net" ) };
	α Ssl::NetTag()ι->sp<LogTag>{ return _logTag; }

	α Ssl::DecodeUri( sv x )ι->string{
		auto from_hex = [](char ch) { return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10; };
		string y{}; y.reserve( x.size() );
    for (auto i = x.begin(), n = x.end(); i != n; ++i)
		{
			char ch = *i;
      if( ch == '%' ){
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
	α Ssl::verify_certificate( bool preverified, boost::asio::ssl::verify_context& ctx )ι->bool{
		char subject_name[256];
		X509* cert = X509_STORE_CTX_get_current_cert( ctx.native_handle() );
		X509_NAME_oneline( X509_get_subject_name(cert), subject_name, 256 );
		preverified = true;
		return preverified;
	}

	α Ssl::SendEmpty( sv host, sv target, sv authorization, http::verb verb )ε->string{
		http::request<http::empty_body> req{ verb, string(target), 11 };
		SetRequest( req, host, "application/x-www-form-urlencoded"sv, authorization );
		return Send( req, host, target );
	}

}