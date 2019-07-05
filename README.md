# Master Thesis
This is the code for my master thesis. It's still work in progress, so when you try to compile and run it, it may give errors or it might not work the way you expect. So in that case, just look at the code instead of running it or come back later.

Install instructions:
- Download this folder
- Install libscapi as on: https://github.com/cryptobiu/libscapi/blob/master/build_scripts/INSTALL.md. Make sure you install OpenSSL 1.0.x, instead of newer versions. The code has been tested and found working on Ubuntu 16.04 with OpenSSL 1.0.2g.

Compile:
 - g++ protocol.cpp server.cpp sensor.cpp table.cpp template.cpp -I/home/osboxes -I/home/osboxes/boost_1_64_0 -std=c++14 ../libscapi/libscapi.a -lboost_system -L/home/osboxes/boost_1_64_0/stage/lib -lssl -lcrypto -lgmp

Run:
- ./a.out
