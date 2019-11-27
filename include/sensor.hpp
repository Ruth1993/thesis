/*
*	Created using libscapi (see https://crypto.biu.ac.il/SCAPI/)
*	Authors: Ruth Scholten
*/

#ifndef SENSOR_H
#define SENSOR_H

#include <vector>
#include <tuple>
#include <string>

#include "party.hpp"

using namespace std;

class Sensor : public Party {
private:

public:
	Sensor();

	pair<int, vector<int>> capture(int u, pair<int, int> template_size);

	pair<int, vector<int>> capture(pair<int, int> template_size);

	shared_ptr<Template_enc> encrypt_template(Template T);

	shared_ptr<Template> decrypt_template(shared_ptr<Template_enc> T_enc);

	tuple<int, shared_ptr<Template_enc>, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>>> enroll(int u, pair<int, int> template_size, int min_s, int max_s);

	vector<shared_ptr<AsymmetricCiphertext>> look_up(vector<int> vec_p, shared_ptr<Template_enc> T_enc);

	shared_ptr<AsymmetricCiphertext> add_scores(vector<shared_ptr<AsymmetricCiphertext>> vec_s_enc);

	tuple<vector<shared_ptr<AsymmetricCiphertext>>, vector<shared_ptr<CmtCCommitmentMsg>>, vector<shared_ptr<GroupElement>>> compare_mal(shared_ptr<AsymmetricCiphertext> S_enc, biginteger t, biginteger max_S);

	bool verify_compare(int soundness, vector<shared_ptr<AsymmetricCiphertext>> C_enc, vector<shared_ptr<AsymmetricCiphertext>> C_enc_no_r_ss, vector<shared_ptr<CmtCCommitmentMsg>> commitments_r, vector<shared_ptr<GroupElement>> h);

	bool verify_permutation(vector<shared_ptr<AsymmetricCiphertext>> C_enc, vector<shared_ptr<AsymmetricCiphertext>> C_enc_prime);

	bool verify_permutation2(vector<shared_ptr<AsymmetricCiphertext>> C_enc, vector<shared_ptr<AsymmetricCiphertext>> C_enc_prime);

	bool verify_D1(int soundness, vector<shared_ptr<AsymmetricCiphertext>> B_enc2, vector<shared_ptr<AsymmetricCiphertext>> B_enc);

	vector<shared_ptr<GroupElement>> decrypt_B_enc2(vector<shared_ptr<AsymmetricCiphertext>> B_enc);

	shared_ptr<GroupElement> check_key(vector<shared_ptr<GroupElement>> B, shared_ptr<SymmetricCiphertext> aes_K);

	void test_look_up();

	void test_add_scores();

	vector<shared_ptr<AsymmetricCiphertext>> encrypt_scores(int nr);

	void print_outcomes(int total);

	int usage();

	int main_sh();

	int main_mal();
};

int main(int argc, char* argv[]);

#endif
