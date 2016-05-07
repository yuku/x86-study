TARGET = test.bin
OBJS = crt0.o test.o

CC = gcc
LD = ld
AS = nasm
CFLAGS += -nostdlib -fno-asynchronous-unwind-tables -g -fno-stack-protector -m32
LDFLAGS += -m elf_i386 --entry=start --oformat=binary -Ttext 0x7c00

.PHONY: all
all : $(TARGET)

%.o : %.c Makefile
	$(CC) $(CFLAGS) -c $<

%.o : %.s Makefile
	$(AS) -f elf $<

$(TARGET) : $(OBJS) Makefile
	$(LD) $(LDFLAGS) -o $@ $(OBJS)
