#pragma region defines
#include "SslWorker.h"
#include "Ssl.h"
#include "AsyncSession.h"

#define var const auto

namespace Jde::Ssl
{
	namespace beast = boost::beast;
	namespace net = boost::asio;
	using namespace Jde::Coroutine;
	std::atomic<bool> SslWorker::_mutex{ false };
	sp<SslWorker> SslWorker::_pInstance;
#pragma endregion
	void SslWorker::Push( SslArg&& x )noexcept
	{
		Threading::AtomicGuard l{ SslWorker::_mutex };
		if( IApplication::ShuttingDown() )
			return;
		var create = !_pInstance;
		if( create )
		{
			_pInstance = sp<SslWorker>( new SslWorker{} );
			DBG( "useCount={}"sv, _pInstance.use_count() );
			IApplication::AddShutdown( _pInstance );
			DBG( "useCount={}"sv, _pInstance.use_count() );
		}
		x.SetWorker( _pInstance );
		DBG( "useCount={}"sv, _pInstance.use_count() );
		_pInstance->_queue.Push( move(x) );
		DBG( "useCount={}"sv, _pInstance.use_count() );
		if( create )
			_pInstance->_pThread = make_shared<Threading::InterruptibleThread>( "SslWorker", [&](){_pInstance->Run();} );
	}

	void SslWorker::Shutdown()noexcept
	{
		Threading::AtomicGuard l{ SslWorker::_mutex };
		if( !_pInstance )
			return;
		_pThread->Interrupt();
		_pThread->Join();
		_pThread = nullptr;
		_pInstance = nullptr;
	}
	void SslWorker::Run()noexcept
	{
		var keepAlive = Settings::Get<Duration>( "WorkerkeepAlive" ).value_or( 5s );
		sp<SslWorker> pKeepAlive;
		while( !Threading::GetThreadInterruptFlag().IsSet() || !_queue.empty() )
		{
			if( auto v = _queue.Pop(); v )
			{
				_lastRequest = Clock::now()+keepAlive;
				DBG( "useCount={}"sv, _pInstance.use_count() );
				HandleRequest( std::move(*v) );
				DBG( "useCount={}"sv, _pInstance.use_count() );
			}
			else if( Clock::now()>_lastRequest+keepAlive )
			{
				Threading::AtomicGuard l{ SslWorker::_mutex };
				DBG( "useCount={}"sv, _pInstance.use_count() );
				if( _pInstance.use_count()<4 )//Shutdown & IApp::Objects & _pInstance
				{
					IApplication::RemoveShutdown( _pInstance );
					DBG( "useCount={}"sv, _pInstance.use_count() );
					pKeepAlive = _pInstance;
					_pInstance = nullptr;
					_pThread->Detach();
					break;
				}
				else
					_lastRequest = Clock::now()+keepAlive;
			}
			try
			{
				if( !_ioc.poll() )//TODO catch exception this can throw
					std::this_thread::yield();
			}
			catch( const std::exception& e )
			{
				std::cerr << e.what() << '\n';
			}
		}
		DBG( "~SslWorker::Run()"sv );
	}
	uint SetFileBody( const SslArg& arg, http::request<http::file_body>& req )noexcept(false);
#define CHECK_EC(fnctn) if( ec ) throw BoostCodeException{ ec, fnctn }
	ⓣ Write( const SslArg& arg, function<uint(http::request<T>& req)> setBody )noexcept(false)->http::request<T>
	{
		http::request<T> req{ arg.Verb, arg.Target, 11 };

		req.set( http::field::user_agent, arg.UserAgent.size() ? string{arg.UserAgent} : BOOST_BEAST_VERSION_STRING );
		req.set( http::field::host, string{arg.Host} );
		req.set( http::field::accept_encoding, "gzip" );
		var size = setBody( req );
		if( size )
		{
			req.content_length( size );
			req.set( http::field::content_type, boost::beast::string_view{arg.ContentType.data(), arg.ContentType.size()} );
		}
		if( arg.Authorization.size() )
			req.set( http::field::authorization, boost::beast::string_view{arg.Authorization.data(), arg.Authorization.size()} );
		req.prepare_payload();

		//beast::get_lowest_layer( stream ).expires_after( 30s );
	//	beast::error_code ec;
		//http::async_write( stream, req, yield[ec] ); CHECK_EC( "async_write"sv );
		return req;
	}
/*	ⓣ Write( const SslArg& arg )noexcept(false)
	{
		http::request<T> req;
		if( arg.Body.index()==1 )
			req = Write<http::string_body>( arg, stream, yield, [&arg](http::request<http::string_body>& req){ req.body() = get<string>(arg.Body); return req.body().size();} );
		else if( arg.Body.index()==2 )
			req = Write<http::file_body>( arg, stream, yield, [&arg](http::request<http::file_body>& req){ return SetFileBody( arg, req ); } );
		else
			req = Write<http::empty_body>( arg, stream, yield, [](auto&){return 0;} );
		return req;
	}
	void do_session( SslArg arg, net::io_context& ioc, net::yield_context yield )noexcept
	{
		var& target = arg.Target;
		//var& host = arg.Host;
		auto h = arg.Handle;
		INFO( "starting - {}"sv, target );

		arg.ContextPtr = make_shared<ssl::context>( ssl::context::tlsv12_client );
		arg.ContextPtr->set_verify_mode( ssl::verify_peer );

		arg.ResolverPtr = make_shared<tcp::resolver>( ioc );
		//beast::error_code ec;
		arg.StreamPtr = make_shared<Stream>( ioc, *arg.ContextPtr );
		try
		{
			THROW_IF( !SSL_set_tlsext_host_name(arg.StreamPtr->native_handle(), arg.Host.c_str()), BoostCodeException{boost::system::error_code{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()}} );
			arg.StreamPtr->set_verify_callback( &Ssl::verify_certificate );
			//var endpoints = resolver.async_resolve( host, "443", yield[ec] ); CHECK_EC( "async_resolve" );
			arg.ResolverPtr->async_resolve( arg.Host, "443", [arg]( const beast::error_code& e, const tcp::resolver::results_type& endpoints )
			{
				if( e ){ DBG( "async_resolve - {}"sv, e.message() ); throw "async_resolve";}
				beast::get_lowest_layer( *arg.StreamPtr ).async_connect( endpoints, [arg]( beast::error_code e, tcp::resolver::results_type::endpoint_type et )
				{
					if( e ) DBG( "get_lowest_layer"sv );
					arg.StreamPtr->async_handshake( ssl::stream_base::client, [arg]( const boost::system::error_code& e )
					{
						if( e ) DBG( "async_handshake"sv );;
						auto pReq = make_unique<http::request<http::empty_body>>( arg.Verb, arg.Target, 11 );
						pReq->set( http::field::user_agent, arg.UserAgent.size() ? string{arg.UserAgent} : BOOST_BEAST_VERSION_STRING );
						pReq->set( http::field::host, string{arg.Host} );
						pReq->set( http::field::accept_encoding, "gzip" );
						if( arg.Authorization.size() )
							pReq->set( http::field::authorization, boost::beast::string_view{arg.Authorization.data(), arg.Authorization.size()} );
						pReq->prepare_payload();
						http::async_write( *arg.StreamPtr, *pReq, [arg, pReq2=move(pReq)](const beast::error_code& ec, std::size_t )
						{
							DBG( "async_write<http::empty_body>"sv );
							CHECK_EC( "async_write<http::empty_body>"sv );
							return;
						} );
					});
				} );
			} );
		}
*/
/*			beast::get_lowest_layer( stream ).expires_after( 30s );
			get_lowest_layer( stream ).async_connect( results , yield[ec] ); CHECK_EC( "async_connect" );

			beast::get_lowest_layer(stream).expires_after( 30s );
			stream.async_handshake( ssl::stream_base::client, yield[ec] ); CHECK_EC( "async_handshake" );

			beast::get_lowest_layer( stream ).expires_after( 30s );
			if( arg.Body.index()==1 )
			{
				auto req = Write<http::string_body>( arg, [&arg](http::request<http::string_body>& req){ req.body() = get<string>(arg.Body); return req.body().size();} );
				http::async_write( stream, req, yield[ec] ); CHECK_EC( "async_write<http::string_body>"sv );
			}
			else if( arg.Body.index()==2 )
			{
				auto req = Write<http::file_body>( arg, [&arg](http::request<http::file_body>& req){ return SetFileBody( arg, req ); } );
				http::async_write( stream, req, yield[ec] ); CHECK_EC( "async_write<http::file_body>"sv );
			}
			else
			{
				//http::async_write( stream, req, yield[ec] );
				//auto req = Write<http::empty_body>( arg, [](auto&){return 0;} );
				http::request<http::empty_body> req{ arg.Verb, arg.Target, 11 };
				req.set( http::field::user_agent, arg.UserAgent.size() ? string{arg.UserAgent} : BOOST_BEAST_VERSION_STRING );
				req.set( http::field::host, string{arg.Host} );
				req.set( http::field::accept_encoding, "gzip" );
				if( arg.Authorization.size() )
					req.set( http::field::authorization, boost::beast::string_view{arg.Authorization.data(), arg.Authorization.size()} );
				req.prepare_payload();
				http::async_write( stream, req, [](const beast::error_code& ec, std::size_t )
				{
					DBG( "async_write<http::empty_body>"sv );
					CHECK_EC( "async_write<http::empty_body>"sv );
					return;
				} );
			}
			return;
			http::response<http::dynamic_body> response;
			boost::beast::flat_buffer buffer;
			http::async_read( stream, buffer, response, yield[ec] ); CHECK_EC( "async_read" );

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
				var startHost = location.find_first_of( "//" ); THROW_IF( startHost==string::npos || startHost+3>location.size(), SslException{host, target, resultValue, location} );
				var startTarget = location.find_first_of( "/", startHost+2 );
				SslArg redirect{arg};
				redirect.Host = location.substr( startHost+2, startTarget-startHost-2 );
				redirect.Target = startTarget==string::npos ? string{} : location.substr( startTarget );
				return do_session( move(redirect), ioc, yield );
			}
			var contentEncoding = findHeader( "Content-Encoding"sv );//TODO handle set-cookie
			if( contentEncoding=="gzip" )
			{
				std::istringstream is{ result };
				result = IO::Zip::GZip::Read( is ).str();
			}
			THROW_IF( resultValue!=200 && resultValue!=204, SslException{host, target, resultValue, result} );
			INFO( "finished - {}"sv, target );
			h.promise().get_return_object().Result = TaskResult{ make_shared<string>(move(result)) };
			Coroutine::CoroutinePool::Resume( move(h) );
		}
		catch( Exception& e )
		{
			h.promise().get_return_object().Result = TaskResult{ std::make_exception_ptr(e) };
			return Coroutine::CoroutinePool::Resume( move(h) );
		}*/
/*		stream.async_shutdown( yield[ec] );
    	if( ec && ec != net::error::eof ) // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
			DBG( "stream.shutdown error='{}'"sv, ec.message() );
	}*/

	α SslWorker::HandleRequest( SslArg&& arg )noexcept->void
	{
		//boost::asio::spawn( _ioc, std::bind(&do_session, move(arg), std::ref(_ioc), std::placeholders::_1) );
		make_shared<AsyncSession>( move(arg), _ioc )->Run();
	}
}