#include <iostream>
#include <array>
#include <chrono>
#include <random>
#include <stdlib.h>
#include <time.h>
#include <vector>

#include "sensor.hpp"

#include "../libscapi/include/mid_layer/OpenSSLSymmetricEnc.hpp"
#include "../libscapi/include/primitives/DlogOpenSSL.hpp"
#include "../libscapi/include/mid_layer/ElGamalEnc.hpp"
#include "../libscapi/include/infra/Common.hpp"

using namespace std;

Sensor::Sensor(shared_ptr<OpenSSLDlogZpSafePrime> dlogg) {
	aes_enc = make_shared<OpenSSLCTREncRandomIV>("AES");

	dlog = dlogg;
	elgamal = make_shared<ElGamalOnGroupElementEnc>(dlog);

	auto key_pair = elgamal->generateKey();
	elgamal->setKey(key_pair.first, key_pair.second);
}

vector<unsigned char> Sensor::int_to_byte(int a) {
  vector<unsigned char> result(4);

  for(int i=0; i<4; i++) {
    result[i] = (a >> (8*(3-i)));
  }

  return result;
}

//Convert a byte array to integer
int Sensor::byte_to_int(vector<unsigned char> vec) {
  int result = 0;

  for(int i=0; i<vec.size(); i++) {
    result = (result << 8) + vec[i];
  }

  return result;
}

//Pad input with zeros (least significant bits) to match number of bits
void Sensor::pad(vector<unsigned char> &input, int bits) {
	int i = bits-input.size()*8;
	if(i > 0) {
		for(int j = 0; j<i; j+=8) {
			vector<unsigned char> byte_zeros = int_to_byte(0);
			input.push_back(byte_zeros[0]);
		}
	}
}

//Setup Elgamal threshold system with server
void Sensor::elgamal_setup() {

}

//Encrypt template using ElGamal
shared_ptr<Template_enc> Sensor::encrypt_template(Template T) {
	Template_enc T_enc;

	auto g = dlog->getGenerator();

	for(vector<biginteger> vec_col : T.T) {
		vector<shared_ptr<AsymmetricCiphertext>> vec_col_enc;

		for(biginteger s : vec_col) {
			//first encode s_{i,j} as g^s_{i,j}
			auto s_prime = dlog->exponentiate(g.get(), s);

			GroupElementPlaintext p(s_prime);
			shared_ptr<AsymmetricCiphertext> cipher = elgamal->encrypt(make_shared<GroupElementPlaintext>(p));

			vec_col_enc.push_back(cipher);
		}

		T_enc.add_col(vec_col_enc);
	}

	return make_shared<Template_enc>(T_enc);
}

void Sensor::enroll() {
	//auto dlog = make_shared<OpenSSLDlogZpSafePrime>(128);
	//OpenSSLCTREncRandomIV aes_enc("AES");

	//Step 4: pick k \in_R [0, |G|]
	auto g = dlog->getGenerator();
	biginteger p = dlog->getOrder();

	auto gen = get_seeded_prg();
	biginteger k = getRandomInRange(0, p-1, gen.get()); //generate random k

	//K = g^k
	auto cap_k = dlog->exponentiate(g.get(), k);


	//Step 5: encrypt K

	//Step 6: AES_K(1)
	//First copy cap_k to byte vector in order to use in AES encryption
	vector<unsigned char> vec_cap_k = dlog->decodeGroupElementToByteArray(cap_k.get());
	cout << vec_cap_k.size() << endl;

	pad(vec_cap_k, 128);

	cout << vec_cap_k.size() << endl;

	//byte arr_cap_k[15];
	//copy_byte_vector_to_byte_array(vec_cap_k, &arr_cap_k, 0);
	//print_byte_array(arr_cap_k, vec_cap_k.size(), "");
	SecretKey aes_cap_k = SecretKey(vec_cap_k, "");

	aes_enc->setKey(aes_cap_k);

	vector<unsigned char> vec = int_to_byte(1);
	ByteArrayPlaintext p1(vec);

	shared_ptr<SymmetricCiphertext> cipher = aes_enc->encrypt(&p1);

	shared_ptr<Plaintext> p2 = aes_enc->decrypt(cipher.get());

	cout << "Plaintext before conversion to plaintext: " << byte_to_int(vec) << endl;
	cout << "Plaintext before encryption: " << byte_to_int(p1.getText()) << endl;
	cout << "Ciphertext: " << ((ByteArraySymCiphertext *)cipher.get())->toString() << endl;
	cout << "Plaintext after decryption: " << byte_to_int(((ByteArrayPlaintext *)p2.get())->getText()) << endl;
}

/*
assert vec_p.size() == T_enc.T_enc.size()
assert \forall p in vec_p: 0 <= p < col
*/
vector<shared_ptr<AsymmetricCiphertext>> Sensor::look_up(vector<int> vec_p, shared_ptr<Template_enc> T_enc) {
	vector<shared_ptr<AsymmetricCiphertext>> vec_s_enc;

	vector<vector<shared_ptr<AsymmetricCiphertext>>> T = T_enc->T_enc;

	for(int i=0; i<T.size(); i++) {
		vector<shared_ptr<AsymmetricCiphertext>> vec_col_enc = T[i];
		shared_ptr<AsymmetricCiphertext> s = vec_col_enc[vec_p[i]];

		vec_s_enc.push_back(s);
	}

	return vec_s_enc;
}

shared_ptr<AsymmetricCiphertext> Sensor::add_scores(vector<shared_ptr<AsymmetricCiphertext>>) {
	
}

int main() {
	Sensor ss(make_shared<OpenSSLDlogZpSafePrime>(128));

	Template T(2, 3, 0, 10);
	T.print();

	shared_ptr<Template_enc> T_enc = ss.encrypt_template(T);

	vector<int> vec_p = {0, 1, 2, 3};

	vector<shared_ptr<AsymmetricCiphertext>> vec_s_enc = ss.look_up(vec_p, T_enc);

	//ss.enroll();

	return 0;
}
