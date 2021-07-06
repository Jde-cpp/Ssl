#include "SslCo.h"
#include "./SslWorker.h"

namespace Jde::Ssl
{
	void SslAwaitable::await_suspend( base::THandle h )noexcept
	{
		base::await_suspend( h );
		Arg.Handle = h;
		SslWorker::Push( move(Arg) );
	}
}