all: aes128-cts-pkcs11 test

P11INCDIR=/usr/local/src/SoftHSMv2-with-OpenPGP/src/lib/cryptoki_compat/ 
P11LIBDIR=/usr/local/src/SoftHSMv2-with-OpenPGP/src/lib/.libs
P11LIB=$(P11LIBDIR)/libsofthsm.so 

aes128-cts-pkcs11: aes128-cts-pkcs11.c
	gcc -ggdb3 -DDEBUG -I $(P11INCDIR) -Wl,-rpath=$(P11LIBDIR) $(P11LIB) -o $@ $<

output.txt: aes128-cts-pkcs11
	./aes128-cts-pkcs11 > output.txt

test: testvectors.txt output.txt
	diff -u testvectors.txt output.txt

clean:
	rm -f output.txt aes128-cts-pkcs11
