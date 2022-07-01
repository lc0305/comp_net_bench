CFLAGS_OPT = -Ofast
CFLAGS += -Wall -Wextra $(CFLAGS_OPT) -march=native -fdata-sections -ffunction-sections
LFLAGS += -luring -llz4 -lz

BIN = comp_net_bench

UNAME_S = $(shell uname -s | tr '[:upper:]' '[:lower:]')
ifeq ($(UNAME_S),linux)
LFLAGS += -Wl,--gc-sections
endif
ifeq ($(UNAME_S),darwin)
LFLAGS += -Wl,-dead_strip
endif

main: buf_pool.hpp common.hpp compress.hpp file_cache.hpp http_request_parser.hpp http_response.hpp http_status.hpp main.cpp networking.hpp
	clang++ $(CFLAGS) -std=c++17 $(LFLAGS) main.cpp -o $(BIN)

clean:
	rm *.o *.so $(BIN)

.PHONY: clean