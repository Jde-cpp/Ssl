#include "SslCo.h"
#include "./SslWorker.h"

namespace Jde::Ssl
{
	void SslAwaitable::await_suspend( HCoroutine h )ι
	{
		base::await_suspend( h );
		Arg.Handle = h;
		SslWorker::Push( move(Arg), _sl );
	}
}