# http://nuclear.mutantstargoat.com/articles/make/
#
src = $(wildcard *.cpp)
obj = $(src:.c=.o)

LDFLAGS = -lcrypto
LIBPATH = -L/usr/local/opt/openssl/lib/
INCLUDES = -I/usr/local/opt/openssl/include
CC = g++ -std=c++11

cuckoo: $(obj)
	    $(CC) -o $@ $^ $(LDFLAGS) $(LIBPATH) $(INCLUDES)

.PHONY: clean
clean:
	rm -f $(obj) cuckoo
