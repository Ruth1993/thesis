#ifndef SERVER_H
#define SERVER_H

#include <vector>
#include <array>

#include "template.hpp"
#include "table.hpp"

#include "../libscapi/include/mid_layer/OpenSSLSymmetricEnc.hpp"
#include "../libscapi/include/primitives/DlogOpenSSL.hpp"
#include "../libscapi/include/mid_layer/ElGamalEnc.hpp"
#include "../libscapi/include/infra/Scanner.hpp"
#include "../libscapi/include/infra/ConfigFile.hpp"
#include "../libscapi/include/comm/Comm.hpp"
#include "../libscapi/include/infra/Common.hpp"
#include "../libscapi/include/interactive_mid_protocols/CommitmentScheme.hpp"
#include "../libscapi/include/interactive_mid_protocols/CommitmentSchemePedersen.hpp"

#include <boost/thread/thread.hpp>

using namespace std;

class Server {
private:
	//Channel object
	shared_ptr<CommParty> channel;

	//ElGamal and AES objects
	shared_ptr<OpenSSLCTREncRandomIV> aes_enc;
 	shared_ptr<OpenSSLDlogZpSafePrime> dlog;
	shared_ptr<ElGamalOnGroupElementEnc> elgamal;

	shared_ptr<PrivateKey> sk_sv;
	shared_ptr<PublicKey> pk_shared;

	//Table
	Table table;

public:
	Server(string config_file_path);

	shared_ptr<PublicKey> key_gen();

	void key_setup(shared_ptr<PublicKey> pk_ss);

	void store_table(tuple<int, shared_ptr<Template_enc>, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>>> enrollment);

	shared_ptr<Template_enc> fetch_template(int u);

	vector<shared_ptr<AsymmetricCiphertext>> compare(shared_ptr<AsymmetricCiphertext> cap_s_enc, biginteger t, biginteger max_s);

	vector<shared_ptr<AsymmetricCiphertext>> permute(vector<shared_ptr<AsymmetricCiphertext>> cap_c_enc);

	pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> fetch_key_pair(int u);

	vector<shared_ptr<AsymmetricCiphertext>> calc_vec_B_enc(vector<shared_ptr<AsymmetricCiphertext>> vec_cap_c_enc2, shared_ptr<AsymmetricCiphertext> cap_k_enc2);

	vector<shared_ptr<AsymmetricCiphertext>> D1(vector<shared_ptr<AsymmetricCiphertext>> vec_B_enc);

	int size_table();

	void test_calc_vec_B_enc();

	void test_compare(biginteger t, biginteger max_s);

	void test_permute(biginteger cap_s, biginteger t, biginteger max_s);

	shared_ptr<ElGamalOnGroupElementCiphertext> test_D1(shared_ptr<AsymmetricCiphertext> cipher);

	int usage();

	int main_sh();

	int main_mal();
};

int main(int argc, char* argv[]);

#endif
