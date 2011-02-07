OBJS = helper.o main.o
LIBS = -lpcap
CFLAGS = -O2 -Wall
OUTPUT = dns_snarf

main: $(OBJS)
	gcc -o $(OUTPUT) $(LIBS) $(OBJS)
clean:
	rm -rf $(OUTPUT) $(OBJS)
