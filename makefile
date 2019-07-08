CC					=	g++
CFLAGS			=	-I/home/osboxes
DEPS				=	sensor.hpp server.hpp table.hpp template.hpp
OBJS 				= protocol.o server.o sensor.o table.o template.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

semihonest_key: protocol.cpp server.cpp sensor.cpp table.cpp template.cpp
	$(CC) -o $@ $^ $(CFLAGS) -std=c++14 ../libscapi/libscapi.a -ldl -lboost_log -lboost_system -lboost_thread -lboost_serialization -lboost_filesystem  -lssl -lcrypto -lgmp -lpthread
