
server: server.o
	gcc server.c -o server -lpthread
clean:
	rm server