#ifndef SERVER_H
#define SERVER_H

#include <vector>
#include <array>

#include "template.hpp"
#include "table.hpp"
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

	void store_table(int u, shared_ptr<Template_enc> T_enc, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> key_pair);

	shared_ptr<Template_enc> fetch_template(int u);

	vector<shared_ptr<AsymmetricCiphertext>> compare(shared_ptr<AsymmetricCiphertext> cap_s_enc, biginteger t, biginteger max_s);

	vector<shared_ptr<AsymmetricCiphertext>> permute(vector<shared_ptr<AsymmetricCiphertext>> cap_c_enc);

	pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> fetch_key_pair(int u);

	vector<shared_ptr<AsymmetricCiphertext>> potential_keys(vector<shared_ptr<AsymmetricCiphertext>> vec_cap_c_enc2, shared_ptr<AsymmetricCiphertext> cap_k_enc2);

	void test_compare(biginteger t, biginteger max_s);

	void test_permute(biginteger cap_s, biginteger t, biginteger max_s);

	void test_potential_keys();
};

int main();

#endif
