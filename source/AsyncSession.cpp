#include "AsyncSession.h"
#include <jde/coroutine/Task.h>
#include <jde/Str.h>
#include "./SslException.h"
#include "./SslWorker.h"

#define var const auto
namespace Jde::Ssl
{
	using namespace Jde::Coroutine;
#define PASS_EX(e) {Arg.Handle.promise().get_return_object().SetResult(e); return CoroutinePool::Resume( move(Arg.Handle) ); }
#define SEND_ERROR(ec,msg) PASS_EX( (BoostCodeException{ec,msg}) )
#define CHECK_EC(msg) if(ec) SEND_ERROR( ec, msg )
	void AsyncSession::Run()noexcept
	{
		if( SSL_set_tlsext_host_name(_stream.native_handle(), Arg.Host.c_str()) )
			_resolver.async_resolve( Arg.Host, Arg.Port, beast::bind_front_handler(&AsyncSession::OnResolve, shared_from_this()) );
		else
			SEND_ERROR( (boost::system::error_code{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()}), "SSL_set_tlsext_host_name" );
	}

	void AsyncSession::OnResolve( beast::error_code ec, tcp::resolver::results_type results )noexcept
	{
		CHECK_EC( "async_resolve" )

		beast::get_lowest_layer( _stream ).expires_after( Timeout );
		beast::get_lowest_layer( _stream ).async_connect( results, beast::bind_front_handler(&AsyncSession::OnConnect, shared_from_this()) );
	}

	void AsyncSession::OnConnect( beast::error_code ec, tcp::resolver::results_type::endpoint_type )noexcept
	{
		CHECK_EC( "async_connect" )

		_stream.async_handshake( ssl::stream_base::client, beast::bind_front_handler(&AsyncSession::OnHandshake, shared_from_this()) );
	}

	uint SetFileBody( const SslArg& arg, http::request<http::file_body>& req )noexcept(false);
	void AsyncSession::OnHandshake( beast::error_code ec )noexcept
	{
		CHECK_EC( "async_handshake" )
		beast::get_lowest_layer( _stream ).expires_after( Timeout );
		if( Arg.Body.index()==1 )
			Write<http::string_body>( [this](http::request<http::string_body>& req){ req.body() = get<string>(Arg.Body); return req.body().size();} );
		else if( Arg.Body.index()==2 )
		{
			try
			{
				Write<http::file_body>( [this](http::request<http::file_body>& req){ return SetFileBody( Arg, req ); } );
			}
			catch( const BoostCodeException& e )
				PASS_EX( std::make_exception_ptr(e) )
		}
		else
			Write<http::empty_body>( [](auto&){return 0;} );
	}

	void AsyncSession::OnWrite( beast::error_code ec, uint bytes_transferred )noexcept
	{
		boost::ignore_unused( bytes_transferred );
		CHECK_EC( "async_write" )

		http::async_read( _stream, _buffer, _response, beast::bind_front_handler(&AsyncSession::OnRead, shared_from_this()) );
	}

	void AsyncSession::OnRead( beast::error_code ec, uint bytes_transferred )noexcept
	{
		boost::ignore_unused( bytes_transferred );
		if( ec )
			DBG( "({})async_read={}"sv, ec.value(), ec.message() );
		CHECK_EC( "async_read" )

		var result = boost::beast::buffers_to_string( _response.body().data() );
		var resultValue = _response.result_int();
		var& header = _response.base();
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
			WARN( "redirecting from {}{} to {}"sv, Arg.Host, Arg.Target, location );
			var startHost = location.find_first_of( "//" ); THROW_IF( startHost==string::npos || startHost+3>location.size(), SslException(Arg.Host, Arg.Target, resultValue, location) );
			var startTarget = location.find_first_of( "/", startHost+2 );
			SslArg redirect{ Arg };
			redirect.Host = location.substr( startHost+2, startTarget-startHost-2 );
			redirect.Target = startTarget==string::npos ? string{} : location.substr( startTarget );
			SslWorker::Push( move(redirect) );
		}
		else
		{
			var contentEncoding = findHeader( "Content-Encoding"sv );//TODO handle set-cookie
			sp<string> pUnzipped;
#ifndef _MSC_VER
			if( contentEncoding=="gzip" )
			{
				std::istringstream is{ result };
				pUnzipped = make_shared<string>( IO::Zip::GZip::Read(is).str() );
			}
			else
#endif
				pUnzipped = make_shared<string>( move(result) );
			if( resultValue==200 || resultValue==204 )
			{
				Arg.Handle.promise().get_return_object().SetResult( pUnzipped );
				CoroutinePool::Resume( move(Arg.Handle) );
			}
			else
				PASS_EX( SslException(Arg.Host, Arg.Target, resultValue, result) )
		}
		//https://github.com/boostorg/beast/issues/824
	//	beast::get_lowest_layer( _stream ).expires_after( Timeout );
	//	_stream.async_shutdown( beast::bind_front_handler(&AsyncSession::OnShutdown, shared_from_this()) );
	}

	void AsyncSession::OnShutdown( beast::error_code ec )noexcept
	{
		DBG_IF( ec && ec != boost::asio::error::eof, "shutdown failed - {}"sv, ec.message() ); // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
	}

	uint SetFileBody( const SslArg& arg, http::request<http::file_body>& req )noexcept(false)
	{
		boost::beast::error_code ec;
		http::file_body::value_type body;
		var& path = get<fs::path>( arg.Body );
		body.open( path.string().c_str(), boost::beast::file_mode::read, ec ); THROW_IF( ec, BoostCodeException{ec,"http::file_body::value_type::open"} );
		var size = body.size();
		req.body() = std::move( body );
		return size;
	}
};