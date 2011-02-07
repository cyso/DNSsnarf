OBJS = helper.o main.o
LIBS = -lpcap
CFLAGS = -O2 -Wall
OUTPUT = dns_snarf
ifndef $(DESTDIR)
DESTDIR = ""
endif
CLIENT_OBJS = client.o
CLIENT_OUTPUT = dns_snarf_client

main: $(OBJS) $(CLIENT_OBJS)
	gcc $(CFLAGS) -o $(OUTPUT) $(LIBS) $(OBJS)
	gcc $(CFLAGS) -o $(CLIENT_OUTPUT) $(CLIENT_OBJS)

cap:
	setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' ${OUTPUT}

clean:
	rm -rf $(OUTPUT) $(OBJS) $(CLIENT_OUTPUT) $(CLIENT_OBJS)

install: main
	install $(OUTPUT) $(DESTDIR)/usr/bin/$(OUTPUT)
	install $(CLIENT_OUTPUT) $(DESTDIR)/usr/bin/$(CLIENT_OUTPUT)

uninstall:
	rm -rf $(DESTDIR)/usr/bin/$(OUTPUT)
	rm -rf $(DESTDIR)/usr/bin/$(CLIENT_OUTPUT)

package:
	sudo dpkg-buildpackage -us -uc -tc
