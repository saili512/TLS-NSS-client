all: tlsNSSClient.exe

tlsNSSClient.exe : tlsNSSClient.o
	gcc -o tlsNSSClient tlsNSSClient.o -L /usr/lib/i386-linux-gnu/ -lnss3 -lnspr4 -lssl3 -lcrypto
tlsNSSClient.o : tlsNSSClient.c
	gcc -c tlsNSSClient.c -I /usr/include/nspr
clean:
	rm tlsNSSClient.o tlsNSSClient.exe
