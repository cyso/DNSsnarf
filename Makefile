OBJS = helper.o main.o
LIBS = -lpcap
CFLAGS = -O2 -Wall
OUTPUT = dns_snarf

main: $(OBJS)
	gcc -o $(OUTPUT) $(LIBS) $(OBJS)
	gcc -o client client.c
	setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' ${OUTPUT}
clean:
	rm -rf $(OUTPUT) $(OBJS)
