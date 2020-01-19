CLANG = clang

EXECABLE = map_pinning_fetch

BPFTOOLS = /kernel-src/samples/bpf
BPFLOADER = $(BPFTOOLS)/bpf_load.c

CCINCLUDE += -I/kernel-src/tools/testing/selftests/bpf
CCINCLUDE += -I/kernel-src/samples/bpf
CCINCLUDE += -I/kernel-src/tools/lib
CCINCLUDE += -I/kernel-src/tools/lib/bpf
CCINCLUDE += -I/kernel-src/tools/perf
CCINCLUDE += -I/kernel-src/tools/include


LIBRARY_PATH = -L/usr/local/lib64
BPFSO = -lbpf

.PHONY: clean $(CLANG)  build

clean:
	rm -f *.o *.so $(EXECABLE)


build:
	clang -o $(EXECABLE) -lelf $(CCINCLUDE) $(LIBRARY_PATH) $(BPFSO) \
        $(BPFLOADER) $(EXECABLE:=.c)

.DEFAULT_GOAL := build
