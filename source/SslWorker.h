#pragma once
#include "TypeDefs.h"
#include "Arg.h"

namespace Jde::Ssl
{
	struct SslWorker final: IShutdown
	{
		Ω Push( SslArg&& x )noexcept->void;
		α Shutdown()noexcept->void;
	private:

		α Run()noexcept->void;

		α HandleRequest( SslArg&& x )noexcept->void;
		α Send( SslArg&& x )noexcept->void;

		static sp<SslWorker> _pInstance;
		sp<Threading::InterruptibleThread> _pThread;
		static std::atomic<bool> _mutex;
		QueueMove<SslArg> _queue;
		boost::asio::io_context _ioc;
		TimePoint _lastRequest{ Clock::now() };
	};
}