#include <jde/TypeDefs.h>
DISABLE_WARNINGS
#include <boost/beast/core.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/core.hpp>
#include <nlohmann/json.hpp>
ENABLE_WARNINGS
#include <jde/io/File.h>
#include "../../Framework/source/coroutine/Awaitable.h"
#include "../../Framework/source/threading/Mutex.h"
#include "../../XZ/source/JdeZip.h"
#include "Exports.h"
#include <iomanip>
#ifdef _MSC_VER
#include <codecvt>
#endif
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

namespace Jde
{
	using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
	using std::basic_string_view;
	using std::basic_string;
	using std::basic_ostringstream;
	namespace http = boost::beast::http;
	namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
}