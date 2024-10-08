﻿#pragma once
#ifndef SSL_H
#define SSL_H
DISABLE_WARNINGS
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/remove_whitespace.hpp>
ENABLE_WARNINGS
#include <jde/Str.h>
#include <jde/io/Json.h>
#include "./TypeDefs.h"

#define Φ JDE_SSL_EXPORT auto
namespace Jde{
	namespace Http{
		Φ Send( sv host, sv target, sv body, PortType port=80, sv authorization={}, sv contentType="application/x-www-form-urlencoded", http::verb verb=http::verb::get, flat_map<string,string>* pReturnedHeaders=nullptr )ε->string;
		Φ Send( sv host, sv target, sv body, sv port="80", sv authorization={}, sv contentType="application/x-www-form-urlencoded", http::verb verb=http::verb::get, flat_map<string,string>* pReturnedHeaders=nullptr )ε->string;
	}
	//using namespace Jde::Coroutine;
	namespace Ssl{
		//Φ RsaSign( sv value, sv key )->string;
		Φ DecodeUri( sv str )ι->string;
		Ŧ static Encode( std::basic_string_view<T> str )ι->string;

		template<class T=string> α Decode64( sv s, bool convertFromFileSafe=false )ε->T;

		Ŧ Get( sv host, sv target, sv port="443", sv authorization={} )ε->T;
		Φ SendEmpty( sv host, sv target, sv authorization={}, http::verb verb=http::verb::post )ε->string;
		Ŧ PostFile( sv host, sv target, const fs::path& path, sv contentType="application/x-www-form-urlencoded", sv authorization={} )ε->T;

		Φ verify_certificate( bool preverified, boost::asio::ssl::verify_context& ctx )ι->bool;
		Ŧ SetRequest( http::request<T>& req, sv host, sv contentType="application/x-www-form-urlencoded", sv authorization={}, sv userAgent={} )ι->void;
		Ŧ Send( sv host, sv target, sv body, sv port="443", sv contentType="application/x-www-form-urlencoded", sv authorization={}, http::verb verb=http::verb::post )ε->T{ return Send<T,http::string_body>( host, target, port, [body](http::request<http::string_body>& req){req.body() = body; return body.size();}, contentType, authorization, verb ); }
		template<class TResult, class TBody> α Send( sv host, sv target, sv port, std::function<uint(http::request<TBody>&)> setBody, sv contentType="application/x-www-form-urlencoded", sv authorization={}, http::verb verb=http::verb::post )ε->TResult;
		Ŧ Send( http::request<T>& req, sv host, sv target={}, sv port="443", sv authorization={} )ε->string;
		Φ NetTag()ι->sp<LogTag>;
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define var const auto
	//https://stackoverflow.com/questions/154536/encode-decode-urls-in-c
	template<typename T>
	string Ssl::Encode( std::basic_string_view<T> url )ι{
		ostringstream os;
		std::ostream hexcout{ os.rdbuf() };
		hexcout << std::hex << std::uppercase << std::setfill('0');
		var end = url.data()+url.size();
		for( auto p=url.data(); p<end; ++p ){
			char16_t wch = *p;
			char16_t compare = 128U;
			if( wch<compare ){
				char ch = (char)*p;
				if( isalnum(*p) || ch == '-' || ch == '_' || ch == '.' || ch == '~' )
					os << ch;
				else{
					os << '%';
					int x = ch;
					hexcout << std::setw(2) << x;
				}
			}
			else{
				auto output = [&]( char8_t ch ){
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
	#pragma GCC diagnostic ignored "-Wsubobject-linkage"
	template<> Ξ Ssl::Decode64<vector<byte>>( sv s, bool convertFromFileSafe )ε->vector<byte>{ //https://stackoverflow.com/questions/10521581/base64-encode-using-boost-throw-exception
		string converted = Decode64<string>( s, convertFromFileSafe );
		std::span<byte> bytes{ (byte*)converted.data(), converted.size() };
		return vector<byte>{ bytes.begin(), bytes.end() };
	}

	Ŧ Ssl::Decode64( sv s, bool convertFromFileSafe )ε->T{ //https://stackoverflow.com/questions/10521581/base64-encode-using-boost-throw-exception
		string converted;
		sv text = s;
		if (convertFromFileSafe){
			converted = s;
			text = Str::Replace(Str::Replace(converted, '_', '/'), '-', '+');
		}
		using namespace boost::archive::iterators;
		using TW = transform_width<binary_from_base64<remove_whitespace<string::const_iterator>>, 8, 6>;
		return T{ TW(text.begin()), TW(text.end()) };
	}

	template<typename TBody>
	α Ssl::SetRequest( http::request<TBody>& req, sv host, sv contentType, sv authorization, sv userAgent )ι->void{
		req.set( http::field::user_agent, userAgent.size() ? string{userAgent} : BOOST_BEAST_VERSION_STRING );
		req.set( http::field::host, string{host} );
		req.set( http::field::accept_encoding, "gzip" );
		if( contentType.size() )
			req.set( http::field::content_type, boost::beast::string_view{contentType.data(), contentType.size()} );
		if( authorization.size() )
			req.set( http::field::authorization, boost::beast::string_view{authorization.data(), authorization.size()} );
		req.prepare_payload();
	}

#define _logTag NetTag()
	template<>
	Ξ Ssl::Get( sv host, sv target, sv port, sv authorization )ε->string{
		http::request<http::empty_body> req{ http::verb::get, string(target), 11 };
		SetRequest( req, host, {}, authorization );
		TRACE( "Get {}{}", host, target );
		return Send( req, host, target, port, authorization );
	}

	template<typename TResult>
	α Ssl::Get( sv host, sv target, sv port, sv authorization )ε->TResult{
		var result = Get<string>( host, target, port, authorization );
		var j = Json::Parse( result );
		return j.get<TResult>();
	}
	template<typename TResult>
	α Ssl::PostFile( sv host, sv target, const fs::path& path, sv contentType, sv authorization )ε->TResult{
		auto fnctn = [&path](http::request<http::file_body>& req){
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

	template<>
	Ξ Ssl::Send<string,http::string_body>( sv host, sv target, sv port, std::function<uint(http::request<http::string_body>&)> setBody, sv contentType, sv authorization, http::verb verb )ε->string{
		http::request<http::string_body> req{ verb, string(target), 11 };
		SetRequest( req, host, contentType, authorization );
		req.content_length( setBody(req) );
		return Send( req, host, target, port, authorization );
	}

	template<typename TResult, typename TBody>
	α Ssl::Send( sv host, sv target, sv port, std::function<uint(http::request<TBody>&)> setBody, sv contentType, sv authorization, http::verb verb )ε->TResult{
		auto httpResult = Send<string,http::string_body>( host, target, port, setBody, contentType, authorization, verb );
		//THROW( "not implemented" );
		var j = Json::Parse( httpResult );
		try{
			TResult result;
			from_json( j, result );
			return result;
		}
		catch( const std::exception& e ){
			THROW( "json deserialization error={}", e.what() );
		}
	}

	template<typename TBody>
	α Ssl::Send( http::request<TBody>& req, sv host, sv target, sv port, sv authorization )ε->string{
		boost::asio::io_context ioc;
		ssl::context ctx( ssl::context::tlsv12_client );
      //load_root_certificates( ctx );
		ctx.set_verify_mode( ssl::verify_peer );
		tcp::resolver resolver{ ioc };
		boost::beast::ssl_stream<boost::beast::tcp_stream> stream( ioc, ctx ); //ssl::stream<tcp::socket> stream{ioc, ctx};
		THROW_IFX( !SSL_set_tlsext_host_name(stream.native_handle(), string{host}.c_str()), BoostCodeException(boost::system::error_code{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()}) );
		stream.set_verify_callback( &verify_certificate );
		try{
			var results = resolver.resolve( host, port );
			try{
				boost::beast::get_lowest_layer( stream ).connect( results );
				stream.handshake( ssl::stream_base::client );
			}
			catch( boost::wrapexcept<boost::system::system_error>& e ){
				throw BoostCodeException( e.code() );
			}
			catch( const boost::system::system_error& e ){
				throw BoostCodeException( e.code() );
			}
		}
		catch( boost::wrapexcept<boost::system::system_error>& e ){
			throw BoostCodeException{ e.code(), Jde::format("Could not resolve {}:{}/{}", host, port, target) };//TODO take out format
		}

		http::write( stream, req );
		http::response<http::dynamic_body> response;
		boost::beast::flat_buffer buffer;
		try{
			http::read( stream, buffer, response );
		}
		catch( boost::wrapexcept<boost::system::system_error>& e ){
			throw BoostCodeException{ e.code() };
		}
		catch( const boost::system::system_error& e ){
			throw BoostCodeException{ e.code() };
		}
		var& body = response.body();
		auto result = boost::beast::buffers_to_string( body.data() );
		var resultValue = response.result_int();
		var& header = response.base();
		auto findHeader = [&header]( const CIString& name )->string{
			for( var& h : header ){
				if( h.name_string()==name )
					return string{ h.value() };
			}
			return {};
		};
		if( resultValue==302 ){
			var location = findHeader( "Location"sv );
			WARN( "redirecting from {}{} to {}", host, target, location );
			var startHost = location.find_first_of( "//" ); THROW_IFX( startHost==string::npos || startHost+3>location.size(), NetException(host, target, resultValue, location) );
			var startTarget = location.find_first_of( "/", startHost+2 );
			return Get<string>( location.substr(startHost+2, startTarget-startHost-2), startTarget==string::npos ? string{} : location.substr(startTarget), authorization );
		}
		var contentEncoding = findHeader( "Content-Encoding"sv );//TODO handle set-cookie
		if( contentEncoding=="gzip" ){
			std::istringstream is{ result };
			result = IO::Zip::GZip::Read( is ).str();
		}
		THROW_IFX( resultValue!=200 && resultValue!=204 && resultValue!=302, NetException(host, target, resultValue, move(result), ELogLevel::Error) );

		/*https://github.com/boostorg/beast/issues/824
		boost::beast::error_code ec;
		stream.shutdown( ec );
		const boost::beast::error_code eof{ boost::asio::error::eof };//already_open==1, eof==2
		if( ec != eof )
			DBG( "stream.shutdown error='{}'", ec.message() );
			//THROW( BoostCodeException(ec) );
		*/
		return result;
	}
}
#undef var
#undef Φ
#undef _logTag
#endif