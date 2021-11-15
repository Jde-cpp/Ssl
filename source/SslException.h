﻿namespace Jde
{
	struct SslException : IException
	{
		SslException( sv host, sv target, uint code, sv result, ELogLevel level=ELogLevel::Trace, SRCE )noexcept;
		α Clone()noexcept->sp<IException> override{ return std::make_shared<SslException>(move(*this)); }
		α Log()const noexcept->void override;
		α Ptr()->std::exception_ptr override{ return std::make_exception_ptr(*this); }
		[[noreturn]] α Throw()->void override{ throw *this; }

		const string Host;
		const string Target;
		const uint Code;
		const string Result;
	};

	inline SslException::SslException( sv host, sv target, uint code, sv result, ELogLevel level, const source_location& sl )noexcept:
		IException{ {string{host}, string{target}, std::to_string(code), string{result}}, "{}{} ({}){}", sl }, //"
		Host{ host },
		Target{ target },
		Code{ code },
		Result{ result }
	{
		_level = level;
		_what = format( "{}{} ({}){}", Host, Target, Code, Result );
		Log();
	}

#define var const auto
	Ξ SslException::Log()const noexcept->void
	{
		Logging::Default().log( spdlog::source_loc{FileName(_sl.file_name()).c_str(),(int)_sl.line(),_sl.function_name()}, (spdlog::level::level_enum)_level, _what );
		//if( Logging::Server() )
		//	Logging::LogServer( Logging::Messages::Message{Logging::Message2{_level, _what, _sl.file_name(), _sl.function_name(), _sl.line()}, vector<string>{_args}} );

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

	#undef var
}