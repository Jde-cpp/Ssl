#include "SslWorker.h"
#include "Ssl.h"
#include "AsyncSession.h"

namespace Jde::Ssl
{
	α SslWorker::Push( SslArg&& x, SL sl )ι->void{
		auto p = IO::AsioContextThread();
		ASSERT( p );
		ms<AsyncSession>( move(x), *p, sl )->Run();
	}
}