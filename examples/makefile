all: party1 party2

party1: party1.cpp
	g++ -o party1 party1.cpp -I/home/osboxes -std=c++14 ../../libscapi/libscapi.a -ldl -lboost_log -lboost_system -lboost_thread -lboost_serialization -lboost_filesystem  -lssl -lcrypto -lgmp -lpthread

party2: party2.cpp
	g++ -o party2 party2.cpp -I/home/osboxes -std=c++14 ../../libscapi/libscapi.a -ldl -lboost_log -lboost_system -lboost_thread -lboost_serialization -lboost_filesystem  -lssl -lcrypto -lgmp -lpthread
