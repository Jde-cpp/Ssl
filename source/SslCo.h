#define 🚪 JDE_SSL_EXPORT static auto
namespace Jde
{
	using namespace Jde::Coroutine;
	struct SslAwaitable<T> : IAwaitable<Task2>
	{
		SslAwaitable( http::request<T>&& req, string&& host, string&& target, string&& authorization )noexcept;
		using base=IAwaitable<Task2>;
		void await_suspend( typename base::THandle h )noexcept override{ base::await_suspend( h ); _pPromise = &h.promise(); };
		typename base::TResult await_resume()noexcept override{ base::AwaitResume(); return move(_pPromise->get_return_object().Result); }
	private:
		typename base::TPromise* _pPromise{ nullptr };
		http::request<T> _request;
		string _host;
		string _target;
		string _authorization;
	};
	struct ContextLock : boost::noncopyable//Header <boost/core/noncopyable.hpp>
	{
		ContextLock()noexcept;
		~ContextLock()noexcept;
	};
	struct SslCo
	{
		ⓣ static Send( http::request<T>& req, sv host, sv target={}, sv authorization={} )noexcept->{ return SslAwaitable<T>( move(req), move(host), move(target), move(authorization) ); };
	private:
		static std::atomic<bool> _mutex;
		static std::atomic<bool> _threadRunning;
		static std::atomic<uint> _callers;
		static boost::asio::io_context _ioc;
		friend ContextLock;
	};
	template<class T>
	SslAwaitable::SslAwaitable( http::request<T>&& req, string&& host, string&& target, string&& authorization )noexcept:
		_request{ move(req) },
		_host{ move(host) },
		_target{ move(target) },
		_authorization{ move(_authorization) }
	{}
	template<class T>
	void SslAwaitable::await_suspend( typename base::THandle h )noexcept
	{
		base::await_suspend( h );
		_pPromise = &h.promise();
		ContextLock l;
		ssl::context ctx( ssl::context::tlsv12_client );
		ctx.set_verify_mode( ssl::verify_peer );
		tcp::resolver resolver{ SslCo::_ioc };
		boost::beast::ssl_stream<boost::beast::tcp_stream> stream( SslCo::ioc, ctx ); //ssl::stream<tcp::socket> stream{ioc, ctx};
		if( !SSL_set_tlsext_host_name(stream.native_handle(), string{_host}.c_str()) )
			THROW( BoostCodeException(boost::system::error_code{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()}) );
		stream.set_verify_callback( &verify_certificate );

		resolver.async_resolve( host, "443", [=]( boost::asio::placeholders::error e, onst tcp::resolver::results_type& endpoints )
		{
			if( e ) throw "TODO";
			boost::beast::get_lowest_layer( stream ).async_connect( endpoints, [=]( const boost::system::error_code& e )
			{
				if( e ) throw "TODO";
				stream.async_handshake( ssl::stream_base::client, [=]( const boost::system::error_code& e )
				{
					if( e ) throw "TODO";
					boost::asio::async_write(socket_, request_,
          boost::bind(&client::handle_write_request, this,
            boost::asio::placeholders::error));
				});
			});
		});

		http::write( stream, req );
		http::response<http::dynamic_body> response;
		boost::beast::flat_buffer buffer;
		try
		{
			http::read( stream, buffer, response );
		}
		catch( boost::wrapexcept<boost::system::system_error>& e )
		{
			THROW( BoostCodeException(e.code()) );
		}
		catch( const boost::system::system_error& e )
		{
			THROW( BoostCodeException(e.code()) );
		}
		var& body = response.body();
		auto result = boost::beast::buffers_to_string( body.data() );
		var resultValue = response.result_int();
		var& header = response.base();
		auto findHeader = [&header]( const CIString& name )->string
		{
			for( var& h : header )
			{//	DBG( "[{}]={}"sv, h.name_string(), h.value() );
				if( h.name_string()==name )
					return string{ h.value() };
			}
			return {};
		};
		if( resultValue==302 )
		{
			var location = findHeader( "Location"sv );
			WARN( "redirecting from {}{} to {}"sv, host, target, location );
			var startHost = location.find_first_of( "//" ); if( startHost==string::npos || startHost+3>location.size() ) THROW( SslException(host, target, resultValue, location) );
			var startTarget = location.find_first_of( "/", startHost+2 );
			return Get<string>( location.substr(startHost+2, startTarget-startHost-2), startTarget==string::npos ? string{} : location.substr(startTarget), authorization );
		}
		var contentEncoding = findHeader( "Content-Encoding"sv );//TODO handle set-cookie
		if( contentEncoding=="gzip" )
		{
			std::istringstream is{ result };
			result = IO::Zip::GZip::Read( is ).str();
		}
		if( resultValue!=200 && resultValue!=204 && resultValue!=302 )
			THROW( SslException(host, target, resultValue, result) );

		/*https://github.com/boostorg/beast/issues/824
		boost::beast::error_code ec;
		stream.shutdown( ec );
		const boost::beast::error_code eof{ boost::asio::error::eof };//already_open==1, eof==2
		if( ec != eof )
			DBG( "stream.shutdown error='{}'"sv, ec.message() );
			//THROW( BoostCodeException(ec) );
		*/
		return result;
	}
}