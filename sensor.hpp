#ifndef SENSOR_H
#define SENSOR_H

#include <vector>

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

	shared_ptr<Template_enc> encrypt_template(Template T);

	void enroll();

	vector<shared_ptr<AsymmetricCiphertext>> look_up(vector<int> vec_p, shared_ptr<Template_enc> T_enc);

shared_ptr<AsymmetricCiphertext> add_scores(vector<shared_ptr<AsymmetricCiphertext>>);
};

int main();

#endif
