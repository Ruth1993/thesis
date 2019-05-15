#include <iostream>
#include <array>
#include <chrono>
#include <random>
#include <stdlib.h>
#include <time.h>
#include <vector>

#include "sensor.hpp"

/*
#include "../libscapi/include/mid_layer/OpenSSLSymmetricEnc.hpp"
#include "../libscapi/include/primitives/DlogOpenSSL.hpp"
#include "../libscapi/include/mid_layer/ElGamalEnc.hpp"
#include "../libscapi/include/infra/Common.hpp"*/

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

//Captures vec_p with identity claim u
pair<int, vector<int>> Sensor::capture(pair<int, int> template_size) {
	unsigned seed = chrono::system_clock::now().time_since_epoch().count();
	srand(seed);
	int u = rand();

	cout << "u: " << u << endl;

	vector<int> vec_p;

	int len = pow(2, template_size.second);

	for(int i=0; i<len; i++) {
		unsigned seed = chrono::system_clock::now().time_since_epoch().count();
		srand(seed);
		vec_p.push_back(rand()%len);
		cout << vec_p[i] << endl;
	}

	return make_pair(u, vec_p);
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

tuple<int, shared_ptr<Template_enc>, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>>> Sensor::enroll(pair<int, int> template_size) {
	//Step 1
	pair<int, vector<int>> u_vec_p = capture(template_size);

	//Step 2 Construct Template_enc
	Template T;

	//Step 3 Encrypte template T
	shared_ptr<Template_enc> T_enc = encrypt_template(T);

	//Step 4: pick k \in_R [0, |G|]
	auto g = dlog->getGenerator();
	biginteger p = dlog->getOrder();

	auto gen = get_seeded_prg();
	biginteger k = getRandomInRange(0, p-1, gen.get()); //generate random k

	//K = g^k
	auto cap_k = dlog->exponentiate(g.get(), k);

	//Step 5: encrypt K
	GroupElementPlaintext p_cap_k(cap_k);
	shared_ptr<AsymmetricCiphertext> cap_k_enc = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_cap_k));

	//Step 6: AES_K(1)
	//First copy cap_k to byte vector in order to use in AES encryption
	vector<unsigned char> vec_cap_k = dlog->decodeGroupElementToByteArray(cap_k.get());
	cout << vec_cap_k.size() << endl;

	pad(vec_cap_k, 128);

	cout << vec_cap_k.size() << endl;

	//byte arr_cap_k[15];
	//copy_byte_vector_to_byte_array(vec_cap_k, &arr_cap_k, 0);
	//print_byte_array(arr_cap_k, vec_cap_k.size(), "");
	SecretKey aes_cap_k_sk = SecretKey(vec_cap_k, "");

	aes_enc->setKey(aes_cap_k_sk);

	vector<unsigned char> vec = int_to_byte(1);
	ByteArrayPlaintext p1(vec);

	shared_ptr<SymmetricCiphertext> aes_cap_k = aes_enc->encrypt(&p1);

	/*shared_ptr<Plaintext> p2 = aes_enc->decrypt(cipher.get());

	cout << "Plaintext before conversion to plaintext: " << byte_to_int(vec) << endl;
	cout << "Plaintext before encryption: " << byte_to_int(p1.getText()) << endl;
	cout << "Ciphertext: " << ((ByteArraySymCiphertext *)cipher.get())->toString() << endl;
	cout << "Plaintext after decryption: " << byte_to_int(((ByteArrayPlaintext *)p2.get())->getText()) << endl;*/

	return make_tuple(u_vec_p.first, T_enc, make_pair(cap_k_enc, aes_cap_k));
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

shared_ptr<GroupElement> Sensor::check_key(vector<shared_ptr<GroupElement>> vec_B, shared_ptr<SymmetricCiphertext> aes_K) {
	auto g = dlog->getGenerator();

	auto B_i = dlog->exponentiate(g.get(), 0); //initiate result with g^0 = 1

	for(shared_ptr<GroupElement> B_i : vec_B) {
		vector<unsigned char> B_i_bytes = dlog->decodeGroupElementToByteArray(B_i.get());
		pad(B_i_bytes, 128);

		SecretKey aes_B_i_sk = SecretKey(B_i_bytes, "");
		aes_enc->setKey(aes_B_i_sk);

		shared_ptr<Plaintext> decryption = aes_enc->decrypt(aes_K.get());
		biginteger decryption_int = byte_to_int(((ByteArrayPlaintext *)decryption.get())->getText());

		cout << "decryption_int: " << decryption_int << endl;

		if(decryption_int == 1) {
			B_i = B_i;
			break;
		}
	}

	return B_i;
}

void Sensor::test_look_up() {
	auto g = dlog->getGenerator();

	Template T;
	T.print();

	shared_ptr<Template_enc> T_enc = encrypt_template(T);

	vector<int> vec_p = {0, 1, 2};

	vector<shared_ptr<AsymmetricCiphertext>> vec_s_enc = look_up(vec_p, T_enc);

	for(int i=0; i<vec_s_enc.size(); i++) {
		shared_ptr<AsymmetricCiphertext> s_enc = vec_s_enc[i];
		shared_ptr<Plaintext> g_s = elgamal->decrypt(s_enc.get());
		biginteger s = T.get(i, vec_p[i]);
		auto g_s2 = dlog->exponentiate(g.get(), s);

		cout << "s: " << s << endl;
		cout << "g^s: " << ((OpenSSLZpSafePrimeElement *)g_s2.get())->getElementValue() << endl;
		cout << "Decrypted selected scores: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)g_s.get())->getElement()).get())->getElementValue() << endl;
	}
}

//Add up all scores contained in vec_s_enc
shared_ptr<AsymmetricCiphertext> Sensor::add_scores(vector<shared_ptr<AsymmetricCiphertext>> vec_s_enc) {
	//%TODO add 0 for randomization
	shared_ptr<AsymmetricCiphertext> result = vec_s_enc[0];

	for(int i=1; i<vec_s_enc.size(); i++) {
		result = elgamal->multiply(result.get(), vec_s_enc[i].get());
	}

	return result;
}

void Sensor::test_add_scores() {
	auto g = dlog->getGenerator();
	vector<biginteger> ints;
	vector<shared_ptr<AsymmetricCiphertext>> ciphers;
	biginteger total = 0;

	for(int i=0; i<4; i++) {
		auto gen = get_seeded_prg();
		ints.push_back(getRandomInRange(0, 5, gen.get()));

		auto gi = dlog->exponentiate(g.get(), ints[i]);

		GroupElementPlaintext p(gi);
		shared_ptr<AsymmetricCiphertext> cipher = elgamal->encrypt(make_shared<GroupElementPlaintext>(p));

		ciphers.push_back(cipher);

		total += ints[i];

		cout << ints[i] << endl;
	}

	auto g_total = dlog->exponentiate(g.get(), total);

	shared_ptr<AsymmetricCiphertext> total_score = add_scores(ciphers);
	shared_ptr<Plaintext> plaintext = elgamal->decrypt(total_score.get());

	cout << "total: " << total << endl;
	cout << "g^total: " << ((OpenSSLZpSafePrimeElement *)g_total.get())->getElementValue() << endl;
	cout << "decrypted total score: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)plaintext.get())->getElement()).get())->getElementValue() << endl;
}

int main_ss() {
	Sensor ss(make_shared<OpenSSLDlogZpSafePrime>(128));

	ss.capture(make_pair(3, 2));

	//ss.test_look_up();

	//ss.enroll();

	return 0;
}
