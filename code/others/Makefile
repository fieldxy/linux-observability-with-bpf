all:
	# cd /kernel-src/tools/lib/bpf
	# sudo make && sudo make install prefix=/
	gcc -o sock_example sock_example.c -I/kernel-src/samples/bpf/ -lbpf

clean:
	rm -rf sock_example
