all:
	gcc -c -fPIC a.s
	ld -o libmya.so -shared a.o
	gcc -c -fPIC b.s
	ld -o libmyb.so -shared b.o
