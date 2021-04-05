#pragma once
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/core.hpp>

#include <nlohmann/json.hpp>
/*


#include <boost/asio/connect.hpp>
*/
#include "../../Framework/source/io/File.h"
#include "../../Framework/source/log/Logging.h"
#include "../../Framework/source/TypeDefs.h"
//#include "../../Framework/source/threading/Mutex.h"
#include "Exports.h"
#include <iomanip>
#ifdef _MSC_VER
#include <codecvt>
#endif
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

namespace Jde
{
	using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
	using std::basic_string_view;
	using std::basic_string;
	using std::basic_ostringstream;
	namespace http = boost::beast::http;
	namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
	struct SslException : IOException
	{
		SslException( sv host, sv target, uint code, sv result ):
			IOException( code, "" ),
			Host{ host },
			Target{ target },
			Result{ result }
		{
#ifndef _MSC_VER
			constexpr sv fileName = "/tmp/ssl_error_response.json"sv;
			auto l{ Threading::UniqueLock(string{fileName}) };
			std::ofstream os{ fileName };
			os << result;
#else
			DBG0( result );
#endif
		}
		string Host;
		string Target;
		string Result;
	};
	struct Ssl
	{
		JDE_SSL_EXPORT static string RsaSign( sv value, sv key );
		template<typename T>
		static string Encode2( basic_string_view<T> str )noexcept;
		JDE_SSL_EXPORT static string Encode( sv str )noexcept;

		JDE_SSL_EXPORT static std::string Encode64( const std::string &val );
		JDE_SSL_EXPORT static std::string Decode64( const std::string& s )noexcept(false);

		//static string RsaPemFromModExp( const string& modulus, const string& exponent )noexcept(false);
		JDE_SSL_EXPORT static void Verify( const string& modulus, const string& exponent, const string& decrypted, const string& encrypted )noexcept(false);

		template<typename TResult>
		static TResult Get( sv host, sv target, sv authorization=""sv )noexcept(false);

		template<typename TResult>
		static TResult Send( sv host, sv target, sv body, sv contentType="application/x-www-form-urlencoded"sv, sv authorization=""sv, http::verb verb=http::verb::post )noexcept(false){ return Send<TResult,http::string_body>( host, target, [body](http::request<http::string_body>& req){req.body() = body; return body.size();}, contentType, authorization, verb ); }

		JDE_SSL_EXPORT static string SendEmpty( sv host, sv target, sv authorization=""sv, http::verb verb=http::verb::post )noexcept(false);

		template<typename TResult, typename TBody>
		static TResult Send( sv host, sv target, std::function<uint(http::request<TBody>&)> setBody, sv contentType="application/x-www-form-urlencoded"sv, sv authorization=""sv, http::verb verb=http::verb::post )noexcept(false);

		template<typename TResult>
		static TResult PostFile( sv host, sv target, const fs::path& path, sv contentType="application/x-www-form-urlencoded"sv, sv authorization=""sv )noexcept(false);

	private:
		template<typename TBody>
		static void SetRequest( http::request<TBody>& req, sv host, const std::basic_string_view<char, std::char_traits<char>> contentType="application/x-www-form-urlencoded"sv, sv authorization=""sv )noexcept;
		template<typename TBody>
		static string Send( http::request<TBody>& req, sv host, sv target=""sv )noexcept(false);
		JDE_SSL_EXPORT static bool verify_certificate( bool preverified, boost::asio::ssl::verify_context& ctx )noexcept;
	};
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
	void Ssl::SetRequest( http::request<TBody>& req, sv host, const std::basic_string_view<char, std::char_traits<char>> contentType, sv authorization )noexcept
	{
		req.set( http::field::user_agent, BOOST_BEAST_VERSION_STRING );
		req.set( http::field::host, string{host} );
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
		SetRequest( req, host, ""sv, authorization );
		TRACE( "Get {}{}"sv, host, target );
		return Send( req, host, target );
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
				THROW( BoostCodeException(ec) );
			req.body() = std::move( body );
			return IO::FileUtilities::GetFileSize( path );
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
			//j.get<TResultx>();
			TResultx result2;
			from_json( j, result2 );
			return result2;
		}
		catch( const std::exception& e )
		{
			THROW( Exception(e.what()) );
		}
	}

	template<typename TBody>
	string Ssl::Send( http::request<TBody>& req, sv host, sv target )noexcept(false)//boost::wrapexcept<boost::system::system_error>
	{
		boost::asio::io_context ioc;
		ssl::context ctx(ssl::context::tlsv12_client);//ssl::context ctx{boost::asio::ssl::context::sslv23};
      //load_root_certificates( ctx );
		ctx.set_verify_mode( ssl::verify_peer );
		tcp::resolver resolver{ ioc };
		boost::beast::ssl_stream<boost::beast::tcp_stream> stream( ioc, ctx ); //ssl::stream<tcp::socket> stream{ioc, ctx};
		if( !SSL_set_tlsext_host_name(stream.native_handle(), string{host}.c_str()) )
			THROW( BoostCodeException(boost::system::error_code{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()}) );
		stream.set_verify_callback( &verify_certificate );
		var results = resolver.resolve( host, "443" );
		try
		{
			boost::beast::get_lowest_layer( stream ).connect( results );
			stream.handshake( ssl::stream_base::client );
		}
		catch( boost::wrapexcept<boost::system::system_error>& e )
		{
			THROW( BoostCodeException(e.code()) );
		}
		catch( const boost::system::system_error& e )
		{
			THROW( BoostCodeException(e.code()) );
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
			THROW( BoostCodeException(e.code()) );
		}
		catch( const boost::system::system_error& e )
		{
			THROW( BoostCodeException(e.code()) );
		}
		var& body = response.body();
		var result = boost::beast::buffers_to_string( body.data() );
		if( var resultValue = response.result_int(); resultValue!=200 && resultValue!=204 )
			THROW( SslException(host, target, resultValue, result) );
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