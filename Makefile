CC=gcc
CFLAGS=-fPIC

all: pam_dovecotmd5pwd.so

pam_dovecotmd5pwd.so: pam_dovecotmd5pwd.o
	ld -x --shared -o pam_dovecotmd5pwd.so pam_dovecotmd5pwd.o

clean:
	rm -f *.so *.o

install: all
	cp pam_dovecotmd5pwd.so /lib/security
