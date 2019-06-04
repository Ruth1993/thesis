#include <iostream>

#include "sensor.hpp"
#include "server.hpp"

using namespace std;

int main() {
	auto dlog = make_shared<OpenSSLDlogZpSafePrime>(128);

	const pair<int, int> template_size = make_pair(3,2);
	const int min_s = 0;
	const int max_s = 10;
	const biginteger max_S = template_size.first * max_s;
	const biginteger t = 1;

	Server sv(dlog);
	Sensor ss(dlog);

	//ElGamal threshold key setup
	shared_ptr<PublicKey> pk_sv = sv.key_gen();
	shared_ptr<PublicKey> pk_ss = ss.key_gen();

	sv.key_setup(pk_ss);
	ss.key_setup(pk_sv);

	int u = 1;

	tuple<int, shared_ptr<Template_enc>, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>>> enrollment = ss.enroll(u, template_size, min_s, max_s);

	sv.store_table(enrollment);

	pair<int, vector<int>> u_vec_p = ss.capture(u, template_size);

	shared_ptr<Template_enc> T_enc = sv.fetch_template(u);

	//cout << "T_enc size: " << T_enc->size().first << T_enc->size().second << endl;
	vector<shared_ptr<AsymmetricCiphertext>> vec_s_enc = ss.look_up(u_vec_p.second, T_enc);
	shared_ptr<AsymmetricCiphertext> S_enc = ss.add_scores(vec_s_enc);

	vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc = sv.compare(S_enc, t, max_S);
	vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc_prime = sv.permute(vec_C_enc);
	vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc2 = sv.D1(vec_C_enc);
	pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> key_pair = sv.fetch_key_pair(u_vec_p.first);

	//vector<shared_ptr<AsymmetricCiphertext>> vec_B_enc2 = sv.potential_keys(vec_C_enc2, key_pair.first);

	vector<shared_ptr<GroupElement>> vec_B = ss.decrypt_vec_B_enc(vec_C_enc2);
	//shared_ptr<GroupElement> key = ss.check_key(vec_B, key_pair.second);

	//cout << "Key: " << ((OpenSSLZpSafePrimeElement *)key.get())->getElementValue() << endl;

	return 0;
}
