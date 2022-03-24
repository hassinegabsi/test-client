CC = gcc

all: mosquitto_demo
    

mosquitto_demo:demo.c
	$(CC) -I/home/acoba/Documents/mosquito/mosquitto-2.0.14/include -c -g $^
	$(CC) demo.o -I/home/acoba/Documents/mosquito/ext_dependency/include -I/home/acoba/Documents/mosquito/mosquitto-2.0.14/include -L/home/acoba/Documents/mosquito/mosquitto-2.0.14/lib -L/home/acoba/Documents/mosquito/ext_dependency/lib32 -lmosquitto -lssl -lcrypto -lpthread -ldl -o $@

clean:
	-rm *.o
	-rm mosquitto_demo

