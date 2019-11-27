CCACHE_EXISTS := $(shell ccache -V)
ifdef CCACHE_EXISTS
    CC := ccache $(CC)
    CXX := ccache g++-8
endif
DEBUG ?= 1
CXXFLAGS_BASE = -c -g -pthread -fPIC -std=c++17 -Wall -Wno-unknown-pragmas -DJdeSsl_EXPORTS  -I$(OUT_DIR)
BIN_DIR_BASE:=../../bin/
OUT_DIR_BASE := .obj/
LIB_BASE = 
#-lstdc++fs -lboost_system -lmatio
ifeq ($(DEBUG), 1)
	OUT_DIR=$(OUT_DIR_BASE)debug
	CXXFLAGS= $(CXXFLAGS_BASE) -O0 -fsanitize=address -fno-omit-frame-pointer
	BIN_DIR=$(BIN_DIR_BASE)debug
	LIB=-lasan $(LIB_BASE)
else
	OUT_DIR=$(OUT_DIR_BASE)release
	CXXFLAGS= $(CXXFLAGS_BASE) -march=native -DNDEBUG -O3
	BIN_DIR=$(BIN_DIR_BASE)release
	LIB=$(LIB_BASE)
endif

OUTPUT = $(BIN_DIR)/libJdeSsl.so

# test:
# 	@echo $(DEBUG)
# 	@echo $(OUTPUT)

#CXX=g++-8

OBJECTS = $(OUT_DIR)/Ssl.o
LDFLAGS = -pthread -shared -Wl,-z,origin -Wl,-rpath='$$ORIGIN'

all: $(OUTPUT)
	$(NOECHO) $(NOOP)

$(OUTPUT): $(OUT_DIR)/stdafx.h.gch $(OBJECTS)
	g++-8 $(LDFLAGS) $(OBJECTS) -o$(OUTPUT) $(LIB)

$(OUT_DIR)/stdafx.h.gch: pc.h
	$(CXX) $(CXXFLAGS) ./pc.h -o $(OUT_DIR)/stdafx.h.gch -I$$BOOST_ROOT -I/home/duffyj/code/libraries/json/include -I/home/duffyj/code/libraries/spdlog/include
######################################################################################
$(OUT_DIR)/%.o: %.cpp %.h pc.h
	$(CXX) $(CXXFLAGS) $(INCLUDE) ./$< -o$@ -I$$BOOST_ROOT

clean:
	rm -rf -d $(OUT_DIR)/*.*
	rm -rf -d $(OUTPUT)