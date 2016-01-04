iguana is easy to build. just make sure you have the dev versions of openssl and curl installed

gcc -O2 -o iguana *.c InstantDEX/*.c -lssl -lcrypto -lpthread -lcurl -lm

the above builds native iguana on unix/osx

then just run it and browse to http://127.0.0.1:7778/?method

