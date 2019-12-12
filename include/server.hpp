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
	//Table
	Table table;

public:
	Server();

	void store_table(int u, shared_ptr<Template_enc> T_enc, shared_ptr<AsymmetricCiphertext> c_k, shared_ptr<SymmetricCiphertext> aes_k_1, Signature sig_m, Signature sig_n, shared_ptr<GroupElement> y);

	void store_table(int u, shared_ptr<Template_enc> T_enc, shared_ptr<AsymmetricCiphertext> c_k, shared_ptr<SymmetricCiphertext> aes_k_1);

	shared_ptr<Template_enc> fetch_template(int u);

	Signature fetch_sig_m(int u);

	Signature fetch_sig_n(int u);

	shared_ptr<GroupElement> fetch_y(int u);

	tuple<vector<shared_ptr<AsymmetricCiphertext>>, vector<shared_ptr<AsymmetricCiphertext>>, tuple<vector<biginteger>, vector<biginteger>, pair<vector<shared_ptr<GroupElement>>, vector<shared_ptr<GroupElement>>>>> compare_mal(shared_ptr<AsymmetricCiphertext> S_enc, biginteger t, biginteger max_S);

	void prove_compare(vector<biginteger> r, vector<biginteger> rho, vector<shared_ptr<AsymmetricCiphertext>> C_enc, vector<shared_ptr<AsymmetricCiphertext>> C_enc_prime_prime, vector<shared_ptr<GroupElement>> commitments_r, vector<shared_ptr<GroupElement>> h);

	vector<shared_ptr<AsymmetricCiphertext>> compare(shared_ptr<AsymmetricCiphertext> S_enc, biginteger t, biginteger max_S);

	tuple<vector<shared_ptr<AsymmetricCiphertext>>, vector<biginteger>, vector<vector<int>>> permute(vector<shared_ptr<AsymmetricCiphertext>> C_enc);

	void prove_permutation(vector<shared_ptr<AsymmetricCiphertext>> C_enc, vector<shared_ptr<AsymmetricCiphertext>> C_enc_prime, vector<biginteger> r_i, vector<vector<int>> A);

	void prove_permutation2(vector<shared_ptr<AsymmetricCiphertext>> C_enc, vector<shared_ptr<AsymmetricCiphertext>> C_enc_prime, vector<biginteger> A_0, vector<vector<int>> perm_matrix);

	pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> fetch_key_pair(int u);

	vector<shared_ptr<AsymmetricCiphertext>> calc_B_enc(vector<shared_ptr<AsymmetricCiphertext>> C_enc2, shared_ptr<AsymmetricCiphertext> K_enc2);

	vector<shared_ptr<AsymmetricCiphertext>> D1(vector<shared_ptr<AsymmetricCiphertext>> B_enc);

	void prove_D1(vector<shared_ptr<AsymmetricCiphertext>> B_enc2, vector<shared_ptr<AsymmetricCiphertext>> B_enc);

	int size_table();

	void test_calc_B_enc();

	void test_compare(biginteger t, biginteger max_s);

	void test_permute(int size);

	shared_ptr<ElGamalOnGroupElementCiphertext> test_D1(shared_ptr<AsymmetricCiphertext> cipher);

	int usage();

	int main_sh();

	int main_mal();
};

int main(int argc, char* argv[]);

#endif
