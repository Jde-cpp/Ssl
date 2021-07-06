#pragma once
#include "TypeDefs.h"
#include "Arg.h"

#define var const auto
namespace Jde::Ssl
{
	using boost::beast::error_code;
	namespace beast = boost::beast;
	//https://www.boost.org/doc/libs/1_76_0/libs/beast/example/http/client/async-ssl/http_client_async_ssl.cpp
	struct AsyncSession : public std::enable_shared_from_this<AsyncSession>
	{
		AsyncSession( SslArg&& arg, boost::asio::io_context& ioc )noexcept:Arg{ move(arg) }, _resolver{ioc}, _stream{ioc,_context}{}
		void Run()noexcept;
	private:
		void OnResolve( error_code ec, tcp::resolver::results_type results )noexcept;
		void OnConnect(error_code ec, tcp::resolver::results_type::endpoint_type)noexcept;
		void OnHandshake( error_code ec )noexcept;
		void OnWrite( error_code ec, uint bytes_transferred )noexcept;
		void OnRead( error_code ec, uint bytes_transferred )noexcept;
		void OnShutdown( error_code ec )noexcept;
		ⓣ Write( function<uint(http::request<T>& req)> setBody )noexcept->void;

		SslArg Arg;
		ssl::context _context{ ssl::context::tlsv12_client };
		tcp::resolver _resolver;
		Stream _stream;

		beast::flat_buffer _buffer;
		http::response<http::dynamic_body> _response;
		std::variant<up<http::request<http::empty_body>>, up<http::request<http::string_body>>, up<http::request<http::file_body>>> _pRequest;
		constexpr static Duration Timeout{ 30s };
	};

	ⓣ AsyncSession::Write( function<uint(http::request<T>& req)> setBody )noexcept->void
	{
		auto pReq = make_unique<http::request<T>>( Arg.Verb, Arg.Target, 11 );
		auto& req = *pReq;
		req.set( http::field::user_agent, Arg.UserAgent.size() ? string{Arg.UserAgent} : BOOST_BEAST_VERSION_STRING );
		req.set( http::field::host, string{Arg.Host} );
#ifndef _MSC_VER
		req.set( http::field::accept_encoding, "gzip" );
#endif
		var size = setBody( req );
		if( size )
		{
			req.content_length( size );
			req.set( http::field::content_type, boost::beast::string_view{Arg.ContentType.data(), Arg.ContentType.size()} );
		}
		if( Arg.Authorization.size() )
			req.set( http::field::authorization, boost::beast::string_view{Arg.Authorization.data(), Arg.Authorization.size()} );
		req.prepare_payload();
		_pRequest = move(pReq);
		http::async_write( _stream, req, beast::bind_front_handler(&AsyncSession::OnWrite,shared_from_this()) );
	}
}
#undef var