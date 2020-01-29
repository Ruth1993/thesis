# Master Thesis

Installation Instructions:
- git clone https://github.com/Ruth1993/thesis.git
- Install libscapi as on: https://github.com/cryptobiu/libscapi/tree/dev. If it does not compile, please try https://github.com/Ruth1993/libscapi.
- To check if the installation was successful, build and run the tests as on: https://biulibscapi.readthedocs.io/en/latest/install.html.

For the installation of the partially malicious key release protocol, please carry out the additional steps:
- cd ~/libscapi/include/primitives/Dlog.hpp 
- Change line 811 and/or line 813 (depending on the OS) to the correct file path or copy NISTEC.txt to the specified location. In case folders thesis and libscapi are located in the same folder, change line 811 or 813 to: const string NISTEC\_PROPERTIES\_FILE = "../../libscapi/include/configFiles/NISTEC.txt"
- cd ../.. 
- make

Compile:
- ~/thesis
- make

Run:
Open 2 terminals and run the protocols as follows:
- Semi-honest Key Release Protocol:
	- ./server or ./server sh
	- ./sensor or ./sensor sh
- Partially Malicious Key Release Protocol:
	- ./server mal
	- ./sensor mal

Interpretation of the output:
- For interpretation of the code, send me a message and I will send you my master thesis paper, which explains the protocol that I implemented.
- If the verification procedure was successful, a key will be printed. In case the verification was unsuccessful, the key will be 1.
- In the enrollment procedure, a template T_u belonging to identity u will be created and in the verification procedure, a probe vector vec_p will be created, which are printed, so you can manually check if the selected scores add up to exceeding the threshold. For each column j in T_u, vec_p[j] selects the row containing the partial similarity score.
