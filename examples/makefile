CC					=	g++
CFLAGS			=	-I/home/osboxes
DEPS				=	CommitmentExample.hpp
OBJS 				= CommitmentExample.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

commit: CommitmentExample.cpp
	$(CC) -o $@ $^ $(CFLAGS) -std=c++14 ../../libscapi/libscapi.a -ldl -lboost_log -lboost_system -lboost_thread -lboost_serialization -lboost_filesystem  -lssl -lcrypto -lgmp -lpthread
