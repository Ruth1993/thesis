#include <iostream>

#include "../include/sensor.hpp"
#include "../include/server.hpp"

using namespace std;

int main() {
	auto dlog = make_shared<OpenSSLDlogZpSafePrime>(128);

	const pair<int, int> template_size = make_pair(3,2);
	const int min_s = 0;
	const int max_s = 10;
	const biginteger max_S = template_size.first * max_s;
	const biginteger t = 15;

	Server sv(dlog);
	Sensor ss(dlog);

	auto start_key = chrono::steady_clock::now();
	//ElGamal threshold key setup
	shared_ptr<PublicKey> pk_sv = sv.key_gen();
	shared_ptr<PublicKey> pk_ss = ss.key_gen();

	sv.key_setup(pk_ss);
	ss.key_setup(pk_sv);
	auto end_key = chrono::steady_clock::now();

	cout << "Time elapsed key setup in us: " << chrono::duration_cast<chrono::microseconds>(end_key-start_key).count() << endl;

	cout << endl << "Enrollment procedure: " << endl;

	auto start_enroll = chrono::steady_clock::now();
	int u = 1;

	tuple<int, shared_ptr<Template_enc>, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>>> enrollment = ss.enroll(u, template_size, min_s, max_s);

	sv.store_table(enrollment);
	auto end_enroll = chrono::steady_clock::now();

	cout << "Time elapsed enrollment procedure in us: " << chrono::duration_cast<chrono::microseconds>(end_enroll-start_enroll).count() << endl;

	cout << endl << "Verification protocol: " << endl;

	auto start_protocol = chrono::steady_clock::now();
	pair<int, vector<int>> u_vec_p = ss.capture(u, template_size);

	shared_ptr<Template_enc> T_enc = sv.fetch_template(u);

	vector<shared_ptr<AsymmetricCiphertext>> vec_s_enc = ss.look_up(u_vec_p.second, T_enc);
	shared_ptr<AsymmetricCiphertext> S_enc = ss.add_scores(vec_s_enc);

	vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc = sv.compare(S_enc, t, max_S);
	vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc_prime = sv.permute(vec_C_enc);
	pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> key_pair = sv.fetch_key_pair(u_vec_p.first);
	vector<shared_ptr<AsymmetricCiphertext>> vec_B_enc = sv.calc_vec_B_enc(vec_C_enc_prime, key_pair.first); //TODO change to vec_C_prime
	vector<shared_ptr<AsymmetricCiphertext>> vec_B_enc2 = sv.D1(vec_B_enc);

	vector<shared_ptr<GroupElement>> vec_B = ss.decrypt_vec_B_enc2(vec_B_enc2);
	shared_ptr<GroupElement> key = ss.check_key(vec_B, key_pair.second);
	auto end_protocol = chrono::steady_clock::now();

	cout << "Key: " << ((OpenSSLZpSafePrimeElement *)key.get())->getElementValue() << endl;

	cout << "Time elapsed verification protocol in us: " << chrono::duration_cast<chrono::microseconds>(end_protocol-start_protocol).count() << endl;

	//ss.print_outcomes(template_size.first * max_s);

	return 0;
}
