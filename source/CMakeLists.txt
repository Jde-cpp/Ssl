cmake_minimum_required(VERSION 3.16)
project(Jde.Ssl)
set( CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../../Public/build )
include(common)
#######################################################
set(CMAKE_SHARED_LINKER_FLAGS ${CMAKE_SHARED_LINKER_FLAGS} "-Wl,-rpath=$ORIGIN")

add_library( ${CMAKE_PROJECT_NAME} SHARED Ssl.cpp SslCo.cpp SslWorker.cpp AsyncSession.cpp )
#######################################################
target_link_libraries( ${CMAKE_PROJECT_NAME} Threads::Threads)
target_link_libraries( ${CMAKE_PROJECT_NAME} debug libfmtd.a optimized fmt::libfmt.a )
#######################################################
target_precompile_headers( ${CMAKE_PROJECT_NAME}
  PRIVATE
  <jde/TypeDefs.h>
  <jde/coroutine/Task.h>
	"../../Framework/source/io/AsioContextThread.h"
  "../../Framework/source/coroutine/Awaitable.h"
  "../../Framework/source/threading/InterruptibleThread.h"
)
