#include <iostream>

#include "sensor.hpp"
#include "server.hpp"

using namespace std;

int main() {
	auto dlog = make_shared<OpenSSLDlogZpSafePrime>(128);

	Sensor ss(dlog);
	Server sv(dlog);

	pair<int, vector<int>> u_vec_p = ss.capture(make_pair(3,2));
	Template T;
	shared_ptr<Template_enc> T_enc = ss.encrypt_template(T);
	vector<shared_ptr<AsymmetricCiphertext>> vec_s_enc = ss.look_up(u_vec_p.second, T_enc);
	shared_ptr<AsymmetricCiphertext> S_enc = ss.add_scores(vec_s_enc);

	vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc = sv.compare(S_enc, 6, 10);
	vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc_prime = sv.permute(vec_C_enc);
	pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> key_pair = sv.fetch_key_pair(u_vec_p.first);
	vector<shared_ptr<AsymmetricCiphertext>> vec_B_enc2 = sv.potential_keys(vec_C_enc_prime, key_pair.first);

	vector<shared_ptr<GroupElement>> vec_B = ss.decrypt_vec_B_enc(vec_B_enc2);
	shared_ptr<GroupElement> key = ss.check_key(vec_B, key_pair.second);

	cout << "Key: " << ((OpenSSLZpSafePrimeElement *)key.get())->getElementValue() << endl;

	return 0;
}
