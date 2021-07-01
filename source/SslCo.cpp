#include "SslCo.h"
#include "../../Framework/source/threading/Mutex.h"
#include "./SslWorker.h"

namespace Jde::Ssl
{
	void SslAwaitable::await_suspend( base::THandle h )noexcept
	{
		base::await_suspend( h );
		Arg.Handle = h;
		SslWorker::Push( move(Arg) );
	}
/*	boost::asio::io_context SslCo::_ioc;
	std::atomic<bool> SslCo::_mutex;
	std::atomic<bool> SslCo::_threadRunning;
	std::atomic<uint> SslCo::_callers;

	ContextLock::ContextLock()noexcept
	{
		Threading::AtomicGuard l{ SslCo::_mutex };
		++SslCo::_callers;
		if( !SslCo::_threadRunning.exchange(true) )
		{
			std::thread( []()
			{
				Threading::SetThreadDscrptn( "SslContext" );
 				TimePoint end{ Clock::now()+1min };
				for( ;; )
				{
					if( !SslCo::run() )
					{
						if( end<Clock::now() )
						{
							Threading::AtomicGuard l{ SslCo::_mutex };
							if( !SslCo::_callers )
							{
								SslCo::_threadRunning = false;
								break;
							}
							end = Clock::now()+1min;
						}
						else
							std::this_thread::yield();
					}
					else
						end = Clock::now()+1min;
				}
			}).detach();
		}
	}

	ContextLock::~ContextLock()noexcept
	{
		Threading::AtomicGuard l{ SslCo::_mutex };
		--SslCo::_callers;
	}
*/
}