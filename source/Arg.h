#pragma once
#include "TypeDefs.h"
namespace Jde::Ssl
{
	struct  SslWorker;
	using Stream=boost::beast::ssl_stream<boost::beast::tcp_stream>;

	struct SslArg final
	{
		SslArg( string&& host, string&& target, string&& authorization, str userAgent, ELogLevel level )noexcept:
			Host(move(host)), Target{ move(target) }, Authorization{ move(authorization) }, UserAgent{ userAgent }, Level{ level }
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
		α Path()const noexcept{ return format("{}/{}", Host, Target); }

		string Host;
		string Target;
		string Authorization;
		string UserAgent;
		HCoroutine Handle;
		std::variant<nullptr_t,string,fs::path> Body;
		string ContentType;
		http::verb Verb{ http::verb::get };
		string Port{ "443" };
		const ELogLevel Level{ ELogLevel::Trace };
		sp<tcp::resolver> ResolverPtr;
		sp<ssl::context> ContextPtr;
		sp<Stream> StreamPtr;
	private:
		sp<SslWorker> KeepAlive;
	};
}