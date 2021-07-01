#pragma once
#include <boost/core/noncopyable.hpp>
#include <boost/asio/spawn.hpp>
#include "../../Framework/source/coroutine/Awaitable.h"
#include "./TypeDefs.h"
#include "./Ssl.h"
#include "./SslWorker.h"

#define 🚪 JDE_SSL_EXPORT static auto
#define var const auto
namespace Jde::Ssl
{
	namespace beast = boost::beast;
	namespace net = boost::asio;
	using namespace Jde::Coroutine;

	struct SslAwaitable final : NotReadyErrorAwaitable
	{
		SslAwaitable( SslArg&& arg )noexcept:Arg{move(arg)}{};
		using base=NotReadyErrorAwaitable;
		void await_suspend( base::THandle h )noexcept override;
		//void await_suspend( typename base::THandle h )noexcept override;
		//typename base::TResult await_resume()noexcept override{ base::AwaitResume(); return move(_pPromise->get_return_object().Result); }
	private:
	//	typename base::TPromise* _pPromise{ nullptr };
		SslArg Arg;
	};
	struct ContextLock : boost::noncopyable
	{
		ContextLock()noexcept;
		ContextLock( ContextLock& o )noexcept:ContextLock{}{};
		~ContextLock()noexcept;
	};
	struct SslCo
	{
		//ⓣ static Send( sv host, sv target={}, http::verb verb=http::verb::get, sv authorization={} )noexcept{ return SslAwaitable{ move(req), host, target, authorization }; }
		Ω Send( SslArg&& arg )noexcept{ return SslAwaitable{ move(arg) }; }
		Ω Get( string&& host, string&& target, string&& authorization={}, str userAgent={} )noexcept{ return Send( SslArg{move(host), move(target), move(authorization), userAgent} ); }
		//Ω Get( sv host, sv target, sv authorization={}, sv userAgent={} )noexcept(false){ http::request<http::empty_body> req{ http::verb::get, string(target), 11 }; Ssl::SetRequest( req, host, {}, authorization, userAgent ); return Send( move(req), host, target, authorization ); }
	/*	static boost::asio::io_context _ioc;
	private:
		static bool run()noexcept{ return _ioc.run(); }
		static std::atomic<bool> _mutex;
		static std::atomic<bool> _threadRunning;
		static std::atomic<uint> _callers;
		friend ContextLock;*/
	};

/*	template<class T>
	SslAwaitable::SslAwaitable( sv host, sv target, sv authorization )noexcept:
		_request{ move(req) },
		_host{ host },
		_target{ target },
		_authorization{ authorization }
	{}*/
//#define CHECK_EC if( ec ) {h.promise().get_return_object().Result = TaskResult{ std::make_exception_ptr(BoostCodeException{ec}) }; return Coroutine::CoroutinePool::Resume( move(h) );}
	//template<class T>
	//net::io_context& ioc, ssl::context& ctx,
/*
	void do_session( const string& host, const std::string& port, const std::string& target, IAwaitable<Task2>::THandle h, const http::request<T>& req, net::yield_context yield )
	{
		INFO( "starting - {}"sv, target );
		ContextLock l;

		ssl::context ctx{ssl::context::tlsv12_client};
		ctx.set_verify_mode(ssl::verify_peer);

		tcp::resolver resolver{ SslCo::_ioc };
		boost::beast::ssl_stream<boost::beast::tcp_stream> stream( SslCo::_ioc, ctx );
		if( !SSL_set_tlsext_host_name(stream.native_handle(), host.c_str()) )
		{
			h.promise().get_return_object().Result = TaskResult{ std::make_exception_ptr(BoostCodeException{boost::system::error_code{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()}}) };
			return Coroutine::CoroutinePool::Resume( move(h) );
		}
		stream.set_verify_callback( &Ssl::verify_certificate );
		beast::error_code ec;
		var results = resolver.async_resolve( host, "443", yield[ec] ); CHECK_EC

		beast::get_lowest_layer( stream ).expires_after( 30s );
		get_lowest_layer( stream ).async_connect( results , yield[ec] ); CHECK_EC

		beast::get_lowest_layer(stream).expires_after( 30s );
		stream.async_handshake( ssl::stream_base::client, yield[ec] ); CHECK_EC

	//  http::request<http::string_body> req{http::verb::get, target, version};
	//  req.set(http::field::host, host);
	//  req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

		beast::get_lowest_layer( stream ).expires_after( 30s );
		http::async_write( stream, req, yield[ec] ); CHECK_EC

		http::response<http::dynamic_body> response;
		boost::beast::flat_buffer buffer;
	   http::async_read( stream, buffer, response, yield[ec] ); CHECK_EC

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
		if( resultValue==302 )//TODO test
		{
			var location = findHeader( "Location"sv );
			WARN( "redirecting from {}{} to {}"sv, host, target, location );
			var startHost = location.find_first_of( "//" );
			if( startHost==string::npos || startHost+3>location.size() )
			{
				h.promise().get_return_object().Result = TaskResult{ std::make_exception_ptr(SslException{host, target, resultValue, location}) };
				return Coroutine::CoroutinePool::Resume( move(h) );
			}
			var startTarget = location.find_first_of( "/", startHost+2 );
			return do_session( location.substr(startHost+2, startTarget-startHost-2), port, startTarget==string::npos ? string{} : location.substr(startTarget), h, req, yield );//, ioc, ctx
		}
		var contentEncoding = findHeader( "Content-Encoding"sv );//TODO handle set-cookie
		if( contentEncoding=="gzip" )
		{
			std::istringstream is{ result };
			result = IO::Zip::GZip::Read( is ).str();
		}
		if( resultValue!=200 && resultValue!=204 && resultValue!=302 )
		{
			h.promise().get_return_object().Result = TaskResult{ std::make_exception_ptr(SslException{host, target, resultValue, result}) };
			return Coroutine::CoroutinePool::Resume( move(h) );
		}
		INFO( "finished - {}"sv, target );
		h.promise().get_return_object().Result = TaskResult{ make_shared<string>(move(result)) };
		Coroutine::CoroutinePool::Resume( move(h) );

		stream.async_shutdown( yield[ec] );
    	if( ec && ec != net::error::eof ) // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
			DBG( "stream.shutdown error='{}'"sv, ec.message() );
	}
*/
	//https://www.boost.org/doc/libs/1_76_0/libs/beast/example/http/client/coro-ssl/http_client_coro_ssl.cpp
	//template<class T>
}
#undef 🚪
#undef var
