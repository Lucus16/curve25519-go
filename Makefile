.PHONY: all test clean

all: libsignal-protocol-c/build/src/libsignal-protocol-c.a
	go build

test: libsignal-protocol-c/build/src/libsignal-protocol-c.a
	go test

libsignal-protocol-c/build/src/libsignal-protocol-c.a: libsignal-protocol-c/build/Makefile
	cd libsignal-protocol-c/build && make

libsignal-protocol-c/build/Makefile:
	mkdir -p libsignal-protocol-c/build
	cd libsignal-protocol-c/build && cmake -DCMAKE_BUILD_TYPE=Debug ..

clean:
	rm -rf libsignal-protocol-c/build/
