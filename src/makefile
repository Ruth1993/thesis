all: server sensor

server: server.cpp party.cpp template.cpp table.cpp
	g++ -o server server.cpp party.cpp template.cpp table.cpp -I/home/osboxes -std=c++14 ../../libscapi/libscapi.a -ldl -lboost_log -lboost_system -lboost_thread -lboost_serialization -lboost_filesystem  -lssl -lcrypto -lgmp -lpthread

sensor: sensor.cpp party.cpp template.cpp
	g++ -o sensor sensor.cpp party.cpp template.cpp -I/home/osboxes -std=c++14 ../../libscapi/libscapi.a -ldl -lboost_log -lboost_system -lboost_thread -lboost_serialization -lboost_filesystem  -lssl -lcrypto -lgmp -lpthread
