#ifndef SERVER_H
#define SERVER_H

#include <vector>
#include <array>
#include <string>

#include "table.hpp"
#include "party.hpp"

using namespace std;

class Server : public Party {
private:
	//Protocol parameters
	const biginteger t = 15;

	//Table
	Table table;

public:
	Server(string config_file_path);

	void store_table(int u, shared_ptr<Template_enc> T_enc, shared_ptr<AsymmetricCiphertext> c_k, shared_ptr<SymmetricCiphertext> aes_k_1);

	shared_ptr<Template_enc> fetch_template(int u);

	vector<shared_ptr<AsymmetricCiphertext>> compare(shared_ptr<AsymmetricCiphertext> S_enc, biginteger t, biginteger max_S);

	vector<shared_ptr<AsymmetricCiphertext>> permute(vector<shared_ptr<AsymmetricCiphertext>> C_enc);

	vector<shared_ptr<AsymmetricCiphertext>> permute_mal(vector<shared_ptr<AsymmetricCiphertext>> C_enc);

	pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> fetch_key_pair(int u);

	vector<shared_ptr<AsymmetricCiphertext>> calc_vec_B_enc(vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc2, shared_ptr<AsymmetricCiphertext> cap_k_enc2);

	vector<shared_ptr<AsymmetricCiphertext>> D1(vector<shared_ptr<AsymmetricCiphertext>> vec_B_enc);

	int size_table();

	void test_calc_vec_B_enc();

	void test_compare(biginteger t, biginteger max_s);

	void test_permute(biginteger S, biginteger t, biginteger max_s);

	shared_ptr<ElGamalOnGroupElementCiphertext> test_D1(shared_ptr<AsymmetricCiphertext> cipher);

	int usage();

	int main_sh();

	int main_mal();
};

int main(int argc, char* argv[]);

#endif
