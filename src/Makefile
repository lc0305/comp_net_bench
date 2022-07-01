CFLAGS_DEBUG += -Og -g -fsanitize=address -fno-omit-frame-pointer -D BENCH_DEBUG_PRINT
CFLAGS_RELEASE += -Ofast -march=native
CFLAGS += -Wall -Wextra -std=c++17 -fdata-sections -ffunction-sections
LFLAGS += -luring -llz4 -lz

BIN = comp_net_bench

UNAME_S = $(shell uname -s | tr '[:upper:]' '[:lower:]')
ifeq ($(UNAME_S),linux)
LFLAGS += -Wl,--gc-sections
endif
ifeq ($(UNAME_S),darwin)
LFLAGS += -Wl,-dead_strip
endif

server: buf_pool.hpp common.hpp compress.hpp file_cache.hpp http_request_parser.hpp http_response.hpp http_status.hpp server.cpp networking.hpp
	clang++ $(CFLAGS) $(CFLAGS_RELEASE) $(LFLAGS) server.cpp -o $(BIN)_server

debug: buf_pool.hpp common.hpp compress.hpp file_cache.hpp http_request_parser.hpp http_response.hpp http_status.hpp server.cpp networking.hpp
	clang++ $(CFLAGS) $(CFLAGS_DEBUG) $(LFLAGS) server.cpp -o $(BIN)_server

clean:
	rm *.o *.so $(BIN)*

.PHONY: debug clean