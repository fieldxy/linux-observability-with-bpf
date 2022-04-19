CLANG = clang

EXECABLE = bpfload

BPFCODE = bpf_program

kernel-src = /home/debug/linux-5.10.106

BPFTOOLS = $(kernel-src)/samples/bpf
BPFLOADER = $(BPFTOOLS)/bpf_load.c

BPFTEST = $(kernel-src)/tools/testing/selftests/bpf/trace_helpers.c

CCINCLUDE += -I/$(kernel-src)/tools/testing/selftests/bpf

LOADINCLUDE += -I$(kernel-src)/samples/bpf
LOADINCLUDE += -I$(kernel-src)/tools/lib
LOADINCLUDE += -I$(kernel-src)/tools/perf
LOADINCLUDE += -I$(kernel-src)/tools/include
LOADINCLUDE += -I$(kernel-src)/tools/testing/selftests/bpf
LIBRARY_PATH = -L/usr/local/lib64
BPFSO = -lbpf

.PHONY: clean $(CLANG) bpfload build

clean:
	rm -f *.o *.so $(EXECABLE)

build: ${BPFCODE.c} ${BPFLOADER}
	$(CLANG) -O2 -target bpf -c $(BPFCODE:=.c) $(CCINCLUDE) -o ${BPFCODE:=.o}

bpfload: build
	clang -o $(EXECABLE) -lelf $(LOADINCLUDE) $(LIBRARY_PATH) $(BPFSO) $(BPFLOADER) $(BPFTEST) loader.c

$(EXECABLE): bpfload

.DEFAULT_GOAL := $(EXECABLE)
