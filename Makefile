CFLAGS=-ggdb -Wall -std=gnu99 -fomit-frame-pointer
LDFLAGS=

all:
	@echo "What you want to build?"

unwind-info:

stacker.o: common.h
unwind.o: common.h
stacker: stacker.o unwind.o

clean:
	rm -f stacker unwind-info *.o
