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
#include "../../libscapi/include/mid_layer/ElGamalEnc.hpp"

#include "../include/math.hpp"
#include "../include/template.hpp"

#include <vector>

struct Signature {
	biginteger s;
	biginteger c;
};

class Signer {
private:
	//shared_ptr<OpenSSLDlogZpSafePrime> dlog;
	shared_ptr<OpenSSLDlogECF2m> dlog;
	//shared_ptr<OpenSSLDlogECFp> dlog;

	biginteger alpha;

public:
	shared_ptr<CryptographicHash> H;
	shared_ptr<GroupElement> y;

	Signer();

	Signature sign(vector<byte> msg);
};

class Verifier {
private:
	//shared_ptr<OpenSSLDlogZpSafePrime> dlog;
	shared_ptr<OpenSSLDlogECF2m> dlog;

public:
	shared_ptr<CryptographicHash> H;

	Verifier();

	bool verify(vector<byte> msg, Signature sig, shared_ptr<GroupElement> y);
};

void key_gen(int lambda);

int main_schnorr(int argc, char* argv[]);

#endif
