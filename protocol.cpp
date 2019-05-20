#include <iostream>

#include "sensor.hpp"
#include "server.hpp"

using namespace std;

int main() {
	auto dlog = make_shared<OpenSSLDlogZpSafePrime>(128);

	pair<int, int> template_size = make_pair(3,2);
	int min_s = 0;
	int max_s = 10;
	int t = 5;

	Sensor ss(dlog);
	Server sv(dlog);

	int u = 1;

	tuple<int, shared_ptr<Template_enc>, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>>> enrollment = ss.enroll(u, template_size, min_s, max_s);

	sv.store_table(enrollment);

	cout << "table size server: " << sv.size_table() << endl;

	pair<int, vector<int>> u_vec_p = ss.capture(u, template_size);

	shared_ptr<Template_enc> T_enc = sv.fetch_template(u);

	cout << "T_enc size: " << T_enc->size().first << T_enc->size().second << endl;
	vector<shared_ptr<AsymmetricCiphertext>> vec_s_enc = ss.look_up(u_vec_p.second, T_enc);
	shared_ptr<AsymmetricCiphertext> S_enc = ss.add_scores(vec_s_enc);

	vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc = sv.compare(S_enc, t, max_s);
	vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc_prime = sv.permute(vec_C_enc);
	cout << "before fetch keys" << endl;
	pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> key_pair = sv.fetch_key_pair(u_vec_p.first);
	cout << "after fetch keys" << endl;

	cout << "Size of [C']: " << vec_C_enc_prime.size() << endl;
	/*vector<shared_ptr<AsymmetricCiphertext>> vec_B_enc2 = sv.potential_keys(vec_C_enc_prime, key_pair.first);
	cout << " after potential keys" << endl;*/

	vector<shared_ptr<GroupElement>> vec_B = ss.decrypt_vec_B_enc(vec_C_enc_prime);
	cout << "after decrypt vec_B_enc" << endl;
	//shared_ptr<GroupElement> key = ss.check_key(vec_B, key_pair.second);
	//cout << "after check key" << endl;

	//cout << "Key: " << ((OpenSSLZpSafePrimeElement *)key.get())->getElementValue() << endl;

	return 0;
}
