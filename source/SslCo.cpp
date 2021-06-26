#include "SslCo.h"

namespace Jde
{

	ContextLock::ContextLock()noexcept
	{
		AtomicLock l{ SslCo::_mutex };
		++SslCo::_callers;
		if( !SslCo::_threadRunning.exchange(true) )
		{
			std::thread( []()
			{
				TimePoint end{ Clock::now()+1min };
				for( ;; )
				{
					if( !SslCo::run() )
					{
						if( end<Clock::now() )
						{
							AtomicLock l{ SslCo::_mutex };
							if( !SslCo::_callers )
							{
								SslCo::_threadRunning = false;
								break;
							}
							end = Clock::now()+1min;
						}
						else
							std::current_thread::yield();
					}
					else
						end = Clock::now()+1min;
				}
			}).detach();
		}
	}

	ContextLock::~ContextLock()noexcept
	{
		AtomicLock l{ SslCo::_mutex };
		--SslCo::_callers;
	}


}