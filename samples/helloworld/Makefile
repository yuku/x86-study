BINS = helloworld.bin

.PHONY: all

all: $(BINS)

%.bin: %.s Makefile
	nasm -f bin -o $@ $<
