#include "SslWorker.h"
#include "Ssl.h"
#include "AsyncSession.h"

#define var const auto

namespace Jde::Ssl
{
	SslWorker _instance;
	void SslWorker::Push( SslArg&& x )noexcept
	{
		make_shared<AsyncSession>( move(x), _instance._ioc, _instance )->Run();
	}
}