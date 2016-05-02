BINS = files/helloworld.bin

.PHONY: all

all: $(BINS)

%.o: %.c Makefile
	$(CC) $(CFLAGS) -c $<

%.bin: %.s Makefile
	nasm -f bin -o $@ $<
