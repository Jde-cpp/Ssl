#include "SslWorker.h"
#include "Ssl.h"
#include "AsyncSession.h"
#include "../../Framework/source/io/sockets/Socket.h"

#define var const auto

namespace Jde::Ssl
{
	//SslWorker _instance;
	α SslWorker::Push( SslArg&& x )noexcept->void
	{
		make_shared<AsyncSession>( move(x), IO::Sockets::IOContextThread::Instance()->Context() )->Run();
	}
}