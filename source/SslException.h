namespace Jde
{
	struct SslException : IOException
	{
		SslException( sv host, sv target, uint code, sv result, ELogLevel level=ELogLevel::Trace ):
			IOException( code, "" ),
			Host{ host },
			Target{ target },
			Result{ result }
		{
			_level = level;
#ifdef _MSC_VER
			DBG( result );
#else
			constexpr sv fileName = "/tmp/ssl_error_response.json";
			auto l{ Threading::UniqueLock(string{fileName}) };
			std::ofstream os{ fileName };
			os << result;
#endif
		}
		string Host;
		string Target;
		string Result;
	};
}