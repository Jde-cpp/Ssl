#pragma once
#include "TypeDefs.h"
namespace Jde::Ssl
{
	struct  SslWorker;
	using Stream=boost::beast::ssl_stream<boost::beast::tcp_stream>;

	struct SslArg final
	{
		SslArg( string&& host, string&& target, string&& authorization, str userAgent )noexcept:
			Host(move(host)), Target{ move(target) }, Authorization{ move(authorization) }, UserAgent{ userAgent }
		{}
		SslArg( string&& host, string&& target, string&& authorization, http::verb verb )noexcept:
			Host(move(host)), Target{ move(target) }, Authorization{ move(authorization) }, Verb{ verb }
		{}
		~SslArg()
		{
			if( KeepAlive )
				DBG( "~SslArg::KeepAlive={}"sv, (KeepAlive ? KeepAlive.use_count() : 0) );
		}
		α SetWorker( sp<SslWorker>& p )noexcept{ KeepAlive=p; }

		string Host;
		string Target;
		string Authorization;
		string UserAgent;
		Coroutine::IAwaitable::THandle Handle;
		std::variant<nullptr_t,string,fs::path> Body;
		string ContentType;
		http::verb Verb{ http::verb::get };
		string Port{ "443" };
		sp<tcp::resolver> ResolverPtr;
		sp<ssl::context> ContextPtr;
		sp<Stream> StreamPtr;
	private:
		sp<SslWorker> KeepAlive;
	};
}