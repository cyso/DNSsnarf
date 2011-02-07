OBJS = helper.o main.o
LIBS = -lpcap
CFLAGS = -O2 -Wall
OUTPUT = dns_snarf

main: $(OBJS)
	gcc -o $(OUTPUT) $(LIBS) $(OBJS)
	gcc -o dns_snarf_client client.c

cap:
	setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' ${OUTPUT}

clean:
	rm -rf $(OUTPUT) $(OBJS)

install:
	install dns_snarf /usr/bin/dns_snarf 
	install dns_snarf_client /usr/bin/dns_snarf_client

uninstall:
	rm -rf /usr/bin/dns_snarf
	rm -rf /usr/bin/dns_snarf_client
