#ifndef SERVER_H
#define SERVER_H

#include <vector>
#include <array>

#include "template.hpp"
#include "table.hpp"

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

	shared_ptr<PrivateKey> sk_sv;

	//Table
	Table table;

public:
	Server(shared_ptr<OpenSSLDlogZpSafePrime> dlogg);

	shared_ptr<PublicKey> key_gen();

	void key_setup(shared_ptr<PublicKey> pk_ss);

	shared_ptr<ElGamalOnGroupElementCiphertext> test_partial_decrypt(shared_ptr<AsymmetricCiphertext> cipher);

	void store_table(tuple<int, shared_ptr<Template_enc>, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>>> enrollment);

	shared_ptr<Template_enc> fetch_template(int u);

	vector<shared_ptr<AsymmetricCiphertext>> compare(shared_ptr<AsymmetricCiphertext> cap_s_enc, biginteger t, biginteger max_s);

	vector<shared_ptr<AsymmetricCiphertext>> permute(vector<shared_ptr<AsymmetricCiphertext>> cap_c_enc);

	vector<shared_ptr<AsymmetricCiphertext>> D1(vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc);

	pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> fetch_key_pair(int u);

	vector<shared_ptr<AsymmetricCiphertext>> potential_keys(vector<shared_ptr<AsymmetricCiphertext>> vec_cap_c_enc2, shared_ptr<AsymmetricCiphertext> cap_k_enc2);

	int size_table();

	void test_potential_keys();

	void test_compare(biginteger t, biginteger max_s);

	void test_permute(biginteger cap_s, biginteger t, biginteger max_s);
};

int main_sv();

#endif
