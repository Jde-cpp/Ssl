#!/bin/bash
debug=${1:-1}
clean=${2:-0}
echo "Build SSL"
cd "${0%/*}"
if [ $clean -eq 1 ]; then
	make clean DEBUG=$debug
	if [ $debug -eq 1 ]; then
		ccache g++-8 -c -g -pthread -fPIC -std=c++17 -Wall -Wno-unknown-pragmas -DJdeSsl_EXPORTS  -I.obj/debug -O0 -fsanitize=address -fno-omit-frame-pointer ./pc.h -o .obj/debug/stdafx.h.gch -I$BOOST_ROOT -I/home/duffyj/code/libraries/json/include -I/home/duffyj/code/libraries/spdlog/include
	else
		ccache g++-8 -c -g -pthread -fPIC -std=c++17 -Wall -Wno-unknown-pragmas -DJdeSsl_EXPORTS  -I.obj/release -march=native -DNDEBUG -O3 ./pc.h -o .obj/release/stdafx.h.gch -I$BOOST_ROOT -I/home/duffyj/code/libraries/json/include -I/home/duffyj/code/libraries/spdlog/include
	fi;
	if [ $? -eq 1 ]; then
		exit 1
	fi;
fi
make -j7 DEBUG=$debug
cd -
exit $?