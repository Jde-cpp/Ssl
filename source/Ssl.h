#pragma once
#include <jde/Str.h>
#include "./TypeDefs.h"

#define Φ JDE_SSL_EXPORT auto
namespace Jde
{
	using namespace Jde::Coroutine;
	namespace Ssl
	{
		Φ RsaSign( sv value, sv key )->string;
		Φ Encode( sv str )noexcept->string;
		ⓣ static Encode2( basic_string_view<T> str )noexcept->string;

		Φ Encode64( str val )->string;
		Φ Decode64( str s )noexcept(false)->string;

		//static string RsaPemFromModExp( str modulus, str exponent )noexcept(false);
		Φ Verify( str modulus, str exponent, str decrypted, str encrypted )noexcept(false)->void;

		ⓣ Get( sv host, sv target, sv authorization={} )noexcept(false)->T;

		ⓣ Send( sv host, sv target, sv body, sv contentType="application/x-www-form-urlencoded"sv, sv authorization={}, http::verb verb=http::verb::post )noexcept(false)->T{ return Send<T,http::string_body>( host, target, [body](http::request<http::string_body>& req){req.body() = body; return body.size();}, contentType, authorization, verb ); }

		Φ SendEmpty( sv host, sv target, sv authorization={}, http::verb verb=http::verb::post )noexcept(false)->string;

		template<class TResult, class TBody> static TResult Send( sv host, sv target, std::function<uint(http::request<TBody>&)> setBody, sv contentType="application/x-www-form-urlencoded"sv, sv authorization={}, http::verb verb=http::verb::post )noexcept(false);

		ⓣ PostFile( sv host, sv target, const fs::path& path, sv contentType="application/x-www-form-urlencoded"sv, sv authorization={} )noexcept(false)->T;

		Φ verify_certificate( bool preverified, boost::asio::ssl::verify_context& ctx )noexcept->bool;
		ⓣ SetRequest( http::request<T>& req, sv host, const std::basic_string_view<char, std::char_traits<char>> contentType="application/x-www-form-urlencoded"sv, sv authorization={}, sv userAgent={} )noexcept->void;
		ⓣ Send( http::request<T>& req, sv host, sv target={}, sv authorization={} )noexcept(false)->string;
		Φ NetErrorLevel()ι->ELogLevel;
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define var const auto
	//https://stackoverflow.com/questions/154536/encode-decode-urls-in-c
	template<typename T>
	string Ssl::Encode2( basic_string_view<T> url )noexcept
	{
		ostringstream os;
		std::ostream hexcout{ os.rdbuf() };
		hexcout << std::hex << std::uppercase << std::setfill('0');
		var end = url.data()+url.size();
		for( auto p=url.data(); p<end; ++p )
		{
			char16_t wch = *p;
			char16_t compare = 128U;
			if( wch<compare )
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
				auto output = [&]( char8_t ch )
				{
					os << '%';
					hexcout << std::setw(2) << (uint16_t)ch;//https://stackoverflow.com/questions/1532640/which-iomanip-manipulators-are-sticky
				};
				var upper = (wch>>8) & 0xff;
				if( upper )
					output( upper );
				output( wch & 0xff );
			}
		}
		return os.str();
	}


	template<typename TBody>
	void Ssl::SetRequest( http::request<TBody>& req, sv host, sv contentType, sv authorization, sv userAgent )noexcept
	{
		req.set( http::field::user_agent, userAgent.size() ? string{userAgent} : BOOST_BEAST_VERSION_STRING );
		req.set( http::field::host, string{host} );
		req.set( http::field::accept_encoding, "gzip" );
		if( contentType.size() )
			req.set( http::field::content_type, boost::beast::string_view{contentType.data(), contentType.size()} );
		if( authorization.size() )
			req.set( http::field::authorization, boost::beast::string_view{authorization.data(), authorization.size()} );
		req.prepare_payload();
	}

	template<>
	inline string Ssl::Get( sv host, sv target, sv authorization )noexcept(false)
	{
		http::request<http::empty_body> req{ http::verb::get, string(target), 11 };
		SetRequest( req, host, {}, authorization );
		TRACE( "Get {}{}"sv, host, target );
		return Send( req, host, target, authorization );
	}

	template<typename TResult>
	TResult Ssl::Get( sv host, sv target, sv authorization )noexcept(false)
	{
		var result = Get<string>( host, target, authorization );
		var j = nlohmann::json::parse( result );
		return j.get<TResult>();
	}
	template<typename TResult>
	TResult Ssl::PostFile( sv host, sv target, const fs::path& path, sv contentType, sv authorization )noexcept(false)
	{
		auto fnctn = [&path](http::request<http::file_body>& req)
		{
			boost::beast::error_code ec;
			http::file_body::value_type body;
			body.open( path.string().c_str(), boost::beast::file_mode::read, ec );
			if( ec.value()!=boost::system::errc::success )
				throw BoostCodeException( ec );
			req.body() = std::move( body );
			return IO::FileSize( path );
		};
		return Send<TResult,http::file_body>( host, target, fnctn, contentType, authorization );
	}

	template<typename TResultx, typename TBody>
	TResultx Ssl::Send( sv host, sv target, std::function<uint(http::request<TBody>&)> setBody, sv contentType, sv authorization, http::verb verb )noexcept(false)
	{
		http::request<TBody> req{ verb, string(target), 11 };
		SetRequest( req, host, contentType, authorization );

		req.content_length( setBody(req) );

		var result = Send( req, host );
		var j = nlohmann::json::parse( result );
		try
		{
			TResultx result2;
			from_json( j, result2 );
			return result2;
		}
		catch( const std::exception& e )
		{
			THROW( e.what() );
		}
	}

	template<typename TBody>
	string Ssl::Send( http::request<TBody>& req, sv host, sv target, sv authorization )noexcept(false)//boost::wrapexcept<boost::system::system_error>
	{
		boost::asio::io_context ioc;
		ssl::context ctx( ssl::context::tlsv12_client );
      //load_root_certificates( ctx );
		ctx.set_verify_mode( ssl::verify_peer );
		tcp::resolver resolver{ ioc };
		boost::beast::ssl_stream<boost::beast::tcp_stream> stream( ioc, ctx ); //ssl::stream<tcp::socket> stream{ioc, ctx};
		THROW_IFX( !SSL_set_tlsext_host_name(stream.native_handle(), string{host}.c_str()), BoostCodeException(boost::system::error_code{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()}) );
		stream.set_verify_callback( &verify_certificate );
		try
		{
			var results = resolver.resolve( host, "443" );
			try
			{
				boost::beast::get_lowest_layer( stream ).connect( results );
				stream.handshake( ssl::stream_base::client );
			}
			catch( boost::wrapexcept<boost::system::system_error>& e )
			{
				throw BoostCodeException( e.code() );
			}
			catch( const boost::system::system_error& e )
			{
				throw BoostCodeException( e.code() );
			}
		}
		catch( boost::wrapexcept<boost::system::system_error>& e )
		{
			throw BoostCodeException{ e.code(), format("Could not resolve {}/{}"sv, host, target) };//TODO take out format
		}

		http::write( stream, req );
		http::response<http::dynamic_body> response;
		boost::beast::flat_buffer buffer;
		try
		{
			http::read( stream, buffer, response );
		}
		catch( boost::wrapexcept<boost::system::system_error>& e )
		{
			throw BoostCodeException{ e.code() };
		}
		catch( const boost::system::system_error& e )
		{
			throw BoostCodeException{ e.code() };
		}
		var& body = response.body();
		auto result = boost::beast::buffers_to_string( body.data() );
		var resultValue = response.result_int();
		var& header = response.base();
		auto findHeader = [&header]( const CIString& name )->string
		{
			for( var& h : header )
			{//	DBG( "[{}]={}"sv, h.name_string(), h.value() );
				if( h.name_string()==name )
					return string{ h.value() };
			}
			return {};
		};
		if( resultValue==302 )
		{
			var location = findHeader( "Location"sv );
			WARN( "redirecting from {}{} to {}"sv, host, target, location );
			var startHost = location.find_first_of( "//" ); THROW_IFX( startHost==string::npos || startHost+3>location.size(), NetException(host, target, resultValue, location) );
			var startTarget = location.find_first_of( "/", startHost+2 );
			return Get<string>( location.substr(startHost+2, startTarget-startHost-2), startTarget==string::npos ? string{} : location.substr(startTarget), authorization );
		}
		var contentEncoding = findHeader( "Content-Encoding"sv );//TODO handle set-cookie
		if( contentEncoding=="gzip" )
		{
			std::istringstream is{ result };
			result = IO::Zip::GZip::Read( is ).str();
		}
		THROW_IFX( resultValue!=200 && resultValue!=204 && resultValue!=302, NetException(host, target, resultValue, move(result), NetErrorLevel()) );

		/*https://github.com/boostorg/beast/issues/824
		boost::beast::error_code ec;
		stream.shutdown( ec );
		const boost::beast::error_code eof{ boost::asio::error::eof };//already_open==1, eof==2
		if( ec != eof )
			DBG( "stream.shutdown error='{}'"sv, ec.message() );
			//THROW( BoostCodeException(ec) );
		*/
		return result;
	}
}
#undef var
#undef Φ