main: main.c
	gcc main.c -lpcap -o main

.PHONY: clean
clean:
	rm -f main
