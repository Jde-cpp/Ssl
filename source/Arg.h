#pragma once
#include "TypeDefs.h"
#include "Ssl.h"

#define _logTag Ssl::NetTag()
namespace Jde::Ssl{
	struct  SslWorker;
	using Stream=boost::beast::ssl_stream<boost::beast::tcp_stream>;

	struct SslArg final{
		SslArg( string&& host, string&& target, string&& authorization, str userAgent, ELogLevel level )ι:
			Host(move(host)), Target{ move(target) }, Authorization{ move(authorization) }, UserAgent{ userAgent }, Level{ level }
		{}
		SslArg( string&& host, string&& target, string&& authorization, http::verb verb )ι:
			Host(move(host)), Target{ move(target) }, Authorization{ move(authorization) }, Verb{ verb }
		{}
		~SslArg(){
			if( KeepAlive )
				TRACE( "~SslArg::KeepAlive={}"sv, (KeepAlive ? KeepAlive.use_count() : 0) );
		}
		α SetWorker( sp<SslWorker>& p )ι{ KeepAlive=p; }
		α Path()Ι{ return format("{}/{}", Host, Target); }

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
#undef _logTag