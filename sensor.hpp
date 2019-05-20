#ifndef SENSOR_H
#define SENSOR_H

#include <vector>
#include <tuple>

#include "template.hpp"

#include "../libscapi/include/mid_layer/OpenSSLSymmetricEnc.hpp"
#include "../libscapi/include/primitives/DlogOpenSSL.hpp"
#include "../libscapi/include/mid_layer/ElGamalEnc.hpp"

using namespace std;

class Sensor {
private:
	//ElGamal and AES objects
	shared_ptr<OpenSSLCTREncRandomIV> aes_enc;
 	shared_ptr<OpenSSLDlogZpSafePrime> dlog;
	shared_ptr<ElGamalOnGroupElementEnc> elgamal;

public:
	Sensor(shared_ptr<OpenSSLDlogZpSafePrime> dlogg);

	vector<unsigned char> int_to_byte(int a);

	vector<unsigned char> int_to_byte(int a, int len);

	int byte_to_int(vector<unsigned char> vec);

	void pad(vector<unsigned char> &input, int bytes);

	void elgamal_setup();

	pair<int, vector<int>> capture(int u, pair<int, int> template_size);

	pair<int, vector<int>> capture(pair<int, int> template_size);

	shared_ptr<Template_enc> encrypt_template(Template T);

	tuple<int, shared_ptr<Template_enc>, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>>> enroll(int u, pair<int, int> template_size, int min_s, int max_s);

	vector<shared_ptr<AsymmetricCiphertext>> look_up(vector<int> vec_p, shared_ptr<Template_enc> T_enc);

	shared_ptr<AsymmetricCiphertext> add_scores(vector<shared_ptr<AsymmetricCiphertext>> vec_s_enc);

	shared_ptr<GroupElement> check_key(vector<shared_ptr<GroupElement>> vec_B, shared_ptr<SymmetricCiphertext> aes_K);

	vector<shared_ptr<GroupElement>> decrypt_vec_B_enc(vector<shared_ptr<AsymmetricCiphertext>> vec_B_enc);

	void test_look_up();

	void test_add_scores();
};

int main_ss();

#endif
