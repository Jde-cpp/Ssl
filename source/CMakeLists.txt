cmake_minimum_required(VERSION 3.16)
project(Ssl)
set( CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../../Framework/cmake )
include(SetUpConfigurations)
#set(CMAKE_CXX_FLAGS "-std=c++17")
#https://github.com/boostorg/beast/issues/1916
#######################################################
#if(MSVC)
#	add_compile_options(PRIVATE /W4 /WX)
#else()
#	add_compile_options( -Wall -Wno-unknown-pragmas )
#endif()
#######################################################
#add_link_options( "LINKER:-z,origin-shared" )
#add_link_options( "LINKER:-rpath=$ORIGIN" )
set(CMAKE_SHARED_LINKER_FLAGS ${CMAKE_SHARED_LINKER_FLAGS} "-Wl,-rpath=$ORIGIN")

add_library( Jde.Ssl SHARED Ssl.cpp )
#######################################################
target_link_libraries(Jde.Ssl Threads::Threads)
#######################################################
target_precompile_headers(Jde.Ssl
  PRIVATE
		<boost/crc.hpp>
		<boost/beast/core.hpp>
		<boost/beast/http.hpp>
		<boost/asio/ssl.hpp>
		<boost/beast/version.hpp>
		<boost/asio/ip/tcp.hpp>
		<boost/asio/connect.hpp>
		<boost/system/error_code.hpp>
		<spdlog/spdlog.h>
		<spdlog/sinks/basic_file_sink.h>
		<spdlog/fmt/ostr.h>
		<nlohmann/json.hpp>
		../../Framework/source/DateTime.h
		../../Framework/source/Exception.h
		../../Framework/source/JdeAssert.h
		../../Framework/source/log/Logging.h
		../../Framework/source/TypeDefs.h
		../../Framework/source/io/File.h)
