namespace Jde
{
	struct SslException : IOException
	{
		SslException( sv host, sv target, uint code, sv result ):
			IOException( code, "" ),
			Host{ host },
			Target{ target },
			Result{ result }
		{
#ifndef _MSC_VER
			constexpr sv fileName = "/tmp/ssl_error_response.json"sv;
			auto l{ Threading::UniqueLock(string{fileName}) };
			std::ofstream os{ fileName };
			os << result;
#else
			DBG0( result );
#endif
		}
		string Host;
		string Target;
		string Result;
	};
}