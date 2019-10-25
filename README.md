# Master Thesis
This is the code for my master thesis. It's still work in progress, so when you try to compile and run it, it may give errors or it might not work the way you expect. So in that case, just look at the code instead of running it or come back later.

Install instructions:
- git clone https://github.com/Ruth1993/thesis.git
- Install libscapi as on: https://github.com/cryptobiu/libscapi/tree/dev. If it does not compile, please try https://github.com/Ruth1993/libscapi
- To check if the installation was successful, build and run the tests as on: https://biulibscapi.readthedocs.io/en/latest/install.html

For the installation of the malicious key release protocol, please carry out the additional steps:
- cd ~/libscapi/include/primitives/Dlog.hpp
- Change line 811 and/or line 813 to the correct file path or copy NISTEC.txt to the specified location. In case folders thesis and libscapi are located in the same folder, change line 811 or 813 (depending on the OS you're using) to: const string NISTEC_PROPERTIES_FILE = "../../libscapi/include/configFiles/NISTEC.txt";
- cd ../..
- make


The code has been tested and found working on Ubuntu 16.04 with OpenSSL 1.0.2g.

Compile:
- ~/thesis
- make

Run:
- Semi-honest protocol:
	- ./server or ./server sh
	- ./sensor or ./sensor sh
- Malicious protocol:
	- ./server mal
	- ./sensor mal

Interpretation of the output:
- First of all, please note that the code of the malicious protocol is work in progress, so it will probably give you weird output.
- For interpretation of the code, send me a message and I will send you my master thesis paper (WIP), which explains the protocol that I implemented.
- If the verification procedure was successful, a key will be printed. In case the verification was unsuccessful, the key will be 1.
- In the enrollment procedure, a template T_u belonging to identity u will be created and in the verification procedure, a probe vector vec_p will be created, which are printed, so you can manually check if the selected scores add up to exceeding the threshold. For each column j in T_u, vec_p[j] selects the row containing the partial similarity score.
