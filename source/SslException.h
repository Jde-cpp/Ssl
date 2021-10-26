//#include "../../Framework/source/log/server/ServerSink.h"
namespace Jde
{

#define var const auto
	struct SslException : IException
	{
		SslException( sv host, sv target, uint code, sv result, ELogLevel level=ELogLevel::Trace, SRCE )noexcept:
			IException{ {Host, Target, std::to_string(Code), Result}, "{}{} ({}){}", sl },
			Host{ host },
			Target{ target },
			Code{ code },
			Result{ result }
		{
			_level = level;
			_what = format( "{}{} ({}){}", Host, Target, Code, Result );
			Log();
		}
		
		α Log()const noexcept->void override
		{
			Logging::Default().log( spdlog::source_loc{FileName(_fileName).c_str(),(int)_line,_functionName.data()}, (spdlog::level::level_enum)_level, _what );
			//if( Logging::Server() )
			//	Logging::LogServer( Logging::Messages::Message{Logging::Message2{_level, _what, _fileName, _functionName, _line}, vector<string>{_args}} );

#ifdef _MSC_VER
			try
			{
				var path = fs::temp_directory_path()/"ssl_error_response.json";
				auto l{ Threading::UniqueLock(path.string()) };
				std::ofstream os{ path };
				os << Result;
			}
			catch( std::exception& e )
			{
				ERR( "could not save error result:  {}", e.what() );
			}
#else
			constexpr sv fileName = "/tmp/ssl_error_response.json";
			auto l{ Threading::UniqueLock(string{fileName}) };
			std::ofstream os{ fileName };
			os << Result;
#endif
		}

		const string Host;
		const string Target;
		const uint Code;
		const string Result;
	};
	#undef var
}