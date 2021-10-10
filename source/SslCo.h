#pragma once
#include <boost/core/noncopyable.hpp>
#include "../../Framework/source/coroutine/Awaitable.h"
#include "./Exports.h"
#include "./Arg.h"

namespace Jde::Ssl
{
	using namespace Jde::Coroutine;

	struct JDE_SSL_EXPORT SslAwaitable final : IAwaitable
	{
		using base=IAwaitable;
		SslAwaitable( SslArg&& arg )noexcept:Arg{move(arg)}{};
		α await_suspend( base::THandle h )noexcept->void override;
	private:
		SslArg Arg;
	};

	class SslCo final
	{
		Ω Send( SslArg&& arg )noexcept{ return SslAwaitable{ move(arg) }; }
	public:
		Ω SendEmpty( string&& host, string&& target, string&& authorization={} )noexcept{ return Send( {move(host), move(target), move(authorization), http::verb::post} ); } //??? ContentType="application/x-www-form-urlencoded"
		Ω Get( string&& host, string&& target, string&& authorization={}, str userAgent={}, ELogLevel level=ELogLevel::Trace )noexcept{ return Send( SslArg{move(host), move(target), move(authorization), userAgent, level} ); }
	};
}