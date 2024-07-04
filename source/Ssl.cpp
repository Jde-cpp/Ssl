#include "Ssl.h"

// #include <openssl/engine.h>
// #include <openssl/hmac.h>
// #include <openssl/err.h>
// #include <openssl/evp.h>
// #include <openssl/rsa.h>

//#include <boost/algorithm/hex.hpp>
//#include <jde/Assert.h>
#define var const auto

namespace Jde{
	static sp<Jde::LogTag> _logTag{ Logging::Tag( "net" ) };
	α Ssl::NetTag()ι->sp<LogTag>{ return _logTag; }
	α Http::Send( sv host, sv target, sv body, PortType port, sv authorization, sv contentType, http::verb verb, flat_map<string,string>* pReturnedHeaders )ε->string{
		return Http::Send( host, target, body, std::to_string(port), authorization, contentType, verb, pReturnedHeaders );
	}
	α Http::Send( sv host, sv target, sv body, sv port, sv authorization, sv contentType, http::verb verb, flat_map<string,string>* pReturnedHeaders )ε->string{
		namespace beast = boost::beast;
		boost::asio::io_context ioc;
		tcp::resolver resolver{ ioc };
    beast::tcp_stream stream(ioc);
		var results = resolver.resolve(host, port);
    stream.connect( results );
		http::request<http::string_body> req{ verb, string{target}, 11 };
		req.content_length( body.size() );
		if( !authorization.empty() )
			req.set( http::field::authorization, authorization );
		req.body() = body;
		req.set( http::field::host, host );
		req.set( http::field::content_type, contentType );
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    http::write( stream, req );
    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    http::read( stream, buffer, res );
		var resultValue = res.result_int();
		THROW_IFX( resultValue!=200 && resultValue!=204, NetException(host, target, resultValue, res.body()) );
		if( pReturnedHeaders ){
			var& header = res.base();
			for( var& h : header ){
				if( auto p = pReturnedHeaders->find(h.name_string()); p!=pReturnedHeaders->end() )
					p->second = h.value();
			}
		}
		beast::error_code ec;
		stream.socket().shutdown(tcp::socket::shutdown_both, ec);
		if( ec && ec != beast::errc::not_connected )
				throw beast::system_error{ec};
		return res.body();
	}

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