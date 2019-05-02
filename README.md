# thesis
This is the code for my master thesis. It's still work in progress, so when you try to compile and run it, it may give errors or it might not work the way you expect. So in that case, just look at the code instead of running it or come back later.

Install instructions:
- Download this folder
- Install GMP

Compile:
- g++ protocol.cpp elgamal.cpp template.cpp server.cpp sensor.cpp -o protocol -lgmpxx -lgmp

Run:
- ./protocol
