#include "SslWorker.h"
#include "Ssl.h"
#include "AsyncSession.h"

namespace Jde::Ssl
{
	α SslWorker::Push( SslArg&& x, SL sl )noexcept->void
	{
		ms<AsyncSession>( move(x), IO::AsioContextThread::Instance()->Context(), sl )->Run();
	}
}