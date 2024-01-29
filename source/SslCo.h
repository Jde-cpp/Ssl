#pragma once
#include <boost/core/noncopyable.hpp>
#include "../../Framework/source/coroutine/Awaitable.h"
#include "./Exports.h"
#include "./Arg.h"

namespace Jde::Ssl
{
	using namespace Jde::Coroutine;

	struct JDE_SSL_EXPORT SslAwaitable final : IAwait
	{
		using base=IAwait;
		SslAwaitable( SslArg&& arg, SRCE )ι:IAwait{sl},Arg{move(arg)}{};
		α await_suspend( HCoroutine h )ι->void override;
	private:
		SslArg Arg;
	};

	class SslCo final
	{
		Ω Send( SslArg&& arg, SRCE )ι{ return SslAwaitable{ move(arg), sl }; }
	public:
		Ω SendEmpty( string&& host, string&& target, string&& authorization={} )ι{ return Send( {move(host), move(target), move(authorization), http::verb::post} ); } //??? ContentType="application/x-www-form-urlencoded"
		Ω Get( string&& host, string&& target, string&& authorization={}, str userAgent={}, ELogLevel level=ELogLevel::Trace, SRCE )ι{ return Send( SslArg{move(host), move(target), move(authorization), userAgent, level}, sl ); }
	};
}