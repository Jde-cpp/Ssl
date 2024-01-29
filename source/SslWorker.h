#pragma once
#include "TypeDefs.h"
#include "Arg.h"
#include "../../Framework/source/threading/Worker.h"
#include "AsyncSession.h"

namespace Jde::Ssl
{
	struct JDE_SSL_EXPORT SslWorker final : Threading::IPollWorker
	{
		SslWorker():Threading::IPollWorker{"Ssl"}{}
		Ω Push( SslArg&& x, SL sl )ι->void;
		//void Shutdown()ι override;
	private:
		optional<bool> Poll()ι override{ return _ioc.poll() ? optional<bool>{ true } : _ioc.stopped() ? std::nullopt : optional<bool>{ false }; }
		//void Run( stop_token st )ι override;
		//α HandleRequest( SslArg&& x )ι->void;

		//static sp<SslWorker> _pInstance;
		//sp<Threading::InterruptibleThread> _pThread;
		//static std::atomic<bool> _mutex;
		//QueueMove<SslArg> _queue;
		boost::asio::io_context _ioc;
		//TimePoint _lastRequest{ Clock::now() };
	};
}