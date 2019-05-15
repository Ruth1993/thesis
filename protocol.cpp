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

	vector<shared_ptr<AsymmetricCiphertext>> C_enc = sv.compare(S_enc, 6, 10);
	vector<shared_ptr<AsymmetricCiphertext>> C_enc_prime = sv.permute(C_enc);
	pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> key_pair = sv.fetch_key_pair(u_vec_p.first);

	return 0;
}
