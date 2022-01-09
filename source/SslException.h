namespace Jde
{
	struct SslException : IException
	{
		SslException( sv host, sv target, uint code, sv result, ELogLevel level=ELogLevel::Debug, SRCE )noexcept;
		SslException( SslException&& f )noexcept:IException{ move(f) }, Host{ f.Host }, Target{ f.Target }, Result{ f.Result }{}
		α Log()const noexcept->void override;

		using T=SslException;
		α Clone()noexcept->sp<IException> override{ return ms<T>(move(*this)); }
		α Move()noexcept->up<IException> override{ return mu<T>(move(*this)); }
		α Ptr()->std::exception_ptr override{ return Jde::make_exception_ptr(move(*this)); }
		[[noreturn]] α Throw()->void override{ throw move(*this); }

		const string Host;
		const string Target;
		const string Result;
	};

	inline SslException::SslException( sv host, sv target, uint code, sv result, ELogLevel level, SL sl )noexcept:
		IException{ {string{host}, string{target}, std::to_string(code), string{result}}, "{}{} ({}){}", sl, code }, //"
		Host{ host },
		Target{ target },
		//Code{ code },
		Result{ result }
	{
		_level = level;
		_what = format( "{}{} ({}){}", Host, Target, Code, Result );
		Log();
	}

#define var const auto
	Ξ SslException::Log()const noexcept->void
	{
		var sl = _stack.front();
		Logging::Default().log( spdlog::source_loc{FileName(sl.file_name()).c_str(), (int)sl.line(), sl.function_name()}, (spdlog::level::level_enum)_level, _what );
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