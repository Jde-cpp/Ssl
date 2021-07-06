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
				if( !_ioc.poll() )
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
		return req;
	}

	α SslWorker::HandleRequest( SslArg&& arg )noexcept->void
	{
		make_shared<AsyncSession>( move(arg), _ioc )->Run();
	}
}