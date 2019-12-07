#export CXX=g++-8
cmake_minimum_required(VERSION 3.16)
project(Ssl)
set(CMAKE_CXX_STANDARD 17)
set( CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../../Framework/cmake )
include(SetUpConfigurations)
string(TOLOWER ${CMAKE_BUILD_TYPE} outDir)
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/../../bin/${outDir} )
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
include_directories(  "/home/duffyj/code/libraries/spdlog/include" )
include_directories( "/home/duffyj/code/libraries/json/include" )
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
