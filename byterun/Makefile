all: build

byterun.o: byterun.c
	$(CC) -g -fstack-protector-all -m32 -c byterun.c

utils.o: utils.c
	$(CC) -g -fstack-protector-all -m32 -c utils.c

build: byterun.o utils.o
	$(CC) -m32 -g -o byterun byterun.o utils.o  ../runtime/runtime.a

clean:
	$(RM) *.a *.o *~
