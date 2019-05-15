#ifndef SERVER_H
#define SERVER_H

#include <vector>
#include <array>

#include "template.hpp"
#include "elgamal.hpp"

#include "../libscapi/include/mid_layer/OpenSSLSymmetricEnc.hpp"
#include "../libscapi/include/primitives/DlogOpenSSL.hpp"
#include "../libscapi/include/mid_layer/ElGamalEnc.hpp"

using namespace std;

class Server {
private:
	//ElGamal and AES objects
	shared_ptr<OpenSSLCTREncRandomIV> aes_enc;
 	shared_ptr<OpenSSLDlogZpSafePrime> dlog;
	shared_ptr<ElGamalOnGroupElementEnc> elgamal;

	//Table
	Table table;

public:
	Server(shared_ptr<OpenSSLDlogZpSafePrime> dlogg);

	void store_table();

	shared_ptr<Template_enc> fetch_template(int u);

	vector<shared_ptr<AsymmetricCiphertext>> compare(shared_ptr<AsymmetricCiphertext> cap_s_enc, biginteger t, biginteger max_s);

	vector<shared_ptr<AsymmetricCiphertext>> permute(vector<shared_ptr<AsymmetricCiphertext>> cap_c_enc);

	void test_compare(biginteger t, biginteger max_s);

	void test_permute(biginteger cap_s, biginteger t, biginteger max_s);
};

int main();

#endif
