INC               =  -I../../libscapi/install/include -I../../libscapi/lib/OTExtensionBristol -I../../libscapi/install/include/libOTe \
 -I../install/include/libOTe/cryptoTools
CXX               = g++
LIBS              =  ../../libscapi/install/lib
LINKER_OPTIONS    =  ../../libscapi/libscapi.a $(LIBS)/libOTExtensionBristol.a $(LIBS)/libOTe.a \
 $(LIBS)/libcryptoTools.a $(LIBS)/libmiracl.a $(LIBS)/libsimpleot.a \
  -ldl -lboost_log -lboost_system -lboost_thread -lboost_serialization -lboost_filesystem \
 -lpthread -lgmp -lrt -lssl -lcrypto
CPP_OPTIONS       = --std=c++14 $(INC) -O3 -Wall -Wno-unused-function -Wno-unused-variable -Wno-expansion-to-defined -Wno-ignored-attributes -no-pie
OBJS              = CommitmentExample.o

all: libscapi_example

libscapi_example: $(OBJS)
	$(CXX) $(CPP_OPTIONS) examples_main.cpp -o $@ $(OBJS) $(LINKER_OPTIONS)

%.o: Commitment/%.cpp
	$(CXX) $(CPP_OPTIONS) -c $< -o $@

clean:
	rm -f libscapi_example
	rm -f ./*.o
