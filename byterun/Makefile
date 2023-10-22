all: build

byterun.o: byterun.c
	$(CC) -g -fstack-protector-all -m32 -c byterun.c

build: byterun.o
	$(CC) -m32 -g -o byterun byterun.o ../runtime/runtime.a

clean:
	$(RM) *.a *.o *~
