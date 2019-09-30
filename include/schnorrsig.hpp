/*
*	Created using libscapi (see https://crypto.biu.ac.il/SCAPI/)
*	Authors: Ruth Scholten
*/

#ifndef SCHNORRSIG_H
#define SCHNORRSIG_H

#include "../../libscapi/include/primitives/DlogOpenSSL.hpp"
#include "../../libscapi/include/primitives/Hash.hpp"
#include "../../libscapi/include/primitives/HashOpenSSL.hpp"
#include "../../libscapi/include/infra/Common.hpp"
#include "../../libscapi/include/infra/ConfigFile.hpp"
#include "../../libscapi/include/comm/Comm.hpp"
#include "../../libscapi/include/infra/Scanner.hpp"

#include "../include/math.hpp"

#include <vector>

struct Signature {
	biginteger s;
	vector<byte> c;
};

class Signer {
private:
	shared_ptr<OpenSSLDlogZpSafePrime> dlog;

	biginteger alpha;

public:
	shared_ptr<CryptographicHash> H;
	shared_ptr<GroupElement> y;

	Signer();

	void send_pk(shared_ptr<GroupElement>);

	Signature sign(vector<byte> msg);
};

class Verifier {
private:
	shared_ptr<OpenSSLDlogZpSafePrime> dlog;

public:
	shared_ptr<CryptographicHash> H;

	Verifier();

	shared_ptr<GroupElement> recv_pk();

	bool verify(vector<byte> msg, Signature sig, shared_ptr<GroupElement>);
};

void key_gen(int lambda);

int main(int argc, char* argv[]);

#endif
