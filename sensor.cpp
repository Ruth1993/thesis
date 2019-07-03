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

	auto g = dlog->getGenerator();
	biginteger q = dlog->getOrder();

	//auto key_pair = elgamal->generateKey();
	//elgamal->setKey(key_pair.first, key_pair.second);
}

shared_ptr<PublicKey> Sensor::key_gen() {
	auto pair = elgamal->generateKey();

	pk_ss = pair.first;
	sk_ss = pair.second;

	elgamal->setKey(pk_ss, sk_ss);

	return pk_ss;
}

void Sensor::key_setup(shared_ptr<PublicKey> pk_sv) {
	shared_ptr<GroupElement> h_shared = dlog->exponentiate(((ElGamalPublicKey*) pk_sv.get())->getH().get(), ((ElGamalPrivateKey*) sk_ss.get())->getX());

	cout << "h_shared for sensor: " << ((OpenSSLZpSafePrimeElement *)h_shared.get())->getElementValue() << endl;
	pk_shared = make_shared<ElGamalPublicKey>(ElGamalPublicKey(h_shared));

	elgamal->setKey(pk_shared);
}

shared_ptr<AsymmetricCiphertext> Sensor::test_encrypt() {
	auto g = dlog->getGenerator();
	auto h = dlog->exponentiate(g.get(), 2);
	shared_ptr<AsymmetricCiphertext> cipher = elgamal->encrypt(make_shared<GroupElementPlaintext>(h));

	cout << "random element h is:       " << ((OpenSSLZpSafePrimeElement *)h.get())->getElementValue() << endl;

	auto g2 = dlog->exponentiate(g.get(), 6);

	cout << "g^6 is:       " << ((OpenSSLZpSafePrimeElement *)g2.get())->getElementValue() << endl;

	return cipher;
}

vector<shared_ptr<AsymmetricCiphertext>> Sensor::test_add() {
	vector<shared_ptr<AsymmetricCiphertext>> vec_s;
	shared_ptr<GroupElement> result;

	auto g = dlog->getGenerator();
	auto h1 = dlog->exponentiate(g.get(), 1);
	auto h2 = dlog->exponentiate(g.get(), 3);
	auto h3 = dlog->exponentiate(g.get(), 4);

	GroupElementPlaintext p1(h1);
	GroupElementPlaintext p2(h2);
	GroupElementPlaintext p3(h3);

	shared_ptr<AsymmetricCiphertext> cipher1 = elgamal->encrypt(make_shared<GroupElementPlaintext>(p1));
	shared_ptr<AsymmetricCiphertext> cipher2 = elgamal->encrypt(make_shared<GroupElementPlaintext>(p2));
	shared_ptr<AsymmetricCiphertext> cipher3 = elgamal->encrypt(make_shared<GroupElementPlaintext>(p3));

	vec_s.push_back(cipher1);
	vec_s.push_back(cipher2);
	vec_s.push_back(cipher3);

	result = dlog->multiplyGroupElements(h1.get(), h2.get());
	result = dlog->multiplyGroupElements(result.get(), h3.get());

	cout << "test_add(): result of manual addition is:       " << ((OpenSSLZpSafePrimeElement *)result.get())->getElementValue() << endl;

	return vec_s;
}

void Sensor::print_outcomes() {
	auto g = dlog->getGenerator();

	for(int i=0; i<30; i++) {
			auto h = dlog->exponentiate(g.get(), i);
				cout << "g^" << i << ": " << ((OpenSSLZpSafePrimeElement *)h.get())->getElementValue() << endl;
	}
}

void Sensor::test_decrypt(shared_ptr<ElGamalOnGroupElementCiphertext> cipher) {
	/*elgamal->setKey(pk_ss);
	auto k = dlog->exponentiate(g.get(), 0);
	GroupElementPlaintext p_k(k);
	shared_ptr<AsymmetricCiphertext> E_k = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_k));

	shared_ptr<AsymmetricCiphertext> result = elgamal->multiply(&E_m_prime, ((ElGamalOnGroupElementCiphertext*) E_k.get()));*/
	shared_ptr<Plaintext> plaintext = elgamal->decrypt(cipher.get());
	cout << "decrypted ciphertext is: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)plaintext.get())->getElement()).get())->getElementValue() << endl;
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

//Captures vec_p with identity claim u
pair<int, vector<int>> Sensor::capture(int u, pair<int, int> template_size) {
	cout << "capture(): u: " << u << endl;

	vector<int> vec_p;

	int len = pow(2, template_size.second);

	cout << "vec(p): ";

	for(int i=0; i<template_size.first; i++) {
		//unsigned seed = chrono::system_clock::now().time_since_epoch().count();
		//srand(seed);
		//vec_p.push_back(rand()%len);
		vec_p.push_back(i);
		cout << vec_p[i] << ", ";
	}

	cout << endl;

	return make_pair(u, vec_p);
}

//Captures vec_p with random identity claim u
pair<int, vector<int>> Sensor::capture(pair<int, int> template_size) {
	unsigned seed = chrono::system_clock::now().time_since_epoch().count();
	srand(seed);
	int u = rand();
	cout << "capture(): u: " << u << endl;

	capture(u, template_size);
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

	//cout << "succesfully encrypted template" << endl;

	return make_shared<Template_enc>(T_enc);
}

tuple<int, shared_ptr<Template_enc>, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>>> Sensor::enroll(int u, pair<int, int> template_size, int min_s, int max_s) {
	auto g = dlog->getGenerator();

	//Step 1
	pair<int, vector<int>> u_vec_p = capture(u, template_size);
	//pair<int, vector<int>> u_vec_p = make_pair(1, {0, 0, 0});
	cout << "enrolled with u: " << u << endl;

	//Step 2 Construct Template_enc
	//Template T(template_size, min_s, max_s);
	Template T(template_size, min_s, max_s);
	T.print();

	//Test
	vector<int> vec_p = u_vec_p.second;
	vector<shared_ptr<GroupElement>> vec_s;

	for(int i=0; i<vec_p.size(); i++) {
		biginteger s = T.get(i, vec_p[i]);

		cout << "selected s:       " << s << endl;

		auto gs = dlog->exponentiate(g.get(), s);
		vec_s.push_back(gs);
	}

	shared_ptr<GroupElement> result = vec_s[0];

	for(int i=1; i<vec_s.size(); i++) {
		result = dlog->multiplyGroupElements(result.get(), vec_s[i].get());
	}

	//Step 3 Encrypte template T
	shared_ptr<Template_enc> T_enc = encrypt_template(T);

	//Step 4: pick k \in_R [0, |G|]
	biginteger p = dlog->getOrder();

	auto gen = get_seeded_prg();
	biginteger k = getRandomInRange(0, p-1, gen.get()); //generate random k

	//K = g^k
	auto K = dlog->exponentiate(g.get(), k); //TODO change 2 back to k
	//cout << "[k]:       " << ((OpenSSLZpSafePrimeElement *)K.get())->getElementValue() << endl;

	//Step 5: encrypt K, but first set pk to pk_shared
	elgamal->setKey(pk_shared);
	GroupElementPlaintext p_K(K);
	shared_ptr<AsymmetricCiphertext> K_enc = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_K));

	//Step 6: AES_K(1)
	//First copy K to byte vector in order to use in AES encryption
	vector<unsigned char> vec_K = dlog->decodeGroupElementToByteArray(K.get());
	cout << vec_K.size() << endl;

	pad(vec_K, 128);

	cout << vec_K.size() << endl;

	//byte arr_K[15];
	//copy_byte_vector_to_byte_array(vec_K, &arr_K, 0);
	//print_byte_array(arr_K, vec_K.size(), "");
	SecretKey aes_K_sk = SecretKey(vec_K, "");

	aes_enc->setKey(aes_K_sk);

	vector<unsigned char> vec = int_to_byte(1);
	ByteArrayPlaintext p1(vec);

	shared_ptr<SymmetricCiphertext> aes_K = aes_enc->encrypt(&p1);

	/*shared_ptr<Plaintext> p2 = aes_enc->decrypt(cipher.get());

	cout << "Plaintext before conversion to plaintext: " << byte_to_int(vec) << endl;
	cout << "Plaintext before encryption: " << byte_to_int(p1.getText()) << endl;
	cout << "Ciphertext: " << ((ByteArraySymCiphertext *)cipher.get())->toString() << endl;
	cout << "Plaintext after decryption: " << byte_to_int(((ByteArrayPlaintext *)p2.get())->getText()) << endl;*/

	return make_tuple(u_vec_p.first, T_enc, make_pair(K_enc, aes_K));
}

/*
assert vec_p.size() == T_enc.T_enc.size()
assert \forall p in vec_p: 0 <= p < col
*/
vector<shared_ptr<AsymmetricCiphertext>> Sensor::look_up(vector<int> vec_p, shared_ptr<Template_enc> T_enc) {
	vector<shared_ptr<AsymmetricCiphertext>> vec_s_enc;

	for(int i=0; i<T_enc->size().first; i++) {
		/*vector<shared_ptr<AsymmetricCiphertext>> vec_col_enc = T[i];
		shared_ptr<AsymmetricCiphertext> s = vec_col_enc[vec_p[i]];*/
		shared_ptr<AsymmetricCiphertext> s = T_enc->get_elem(i, vec_p[i]);

		vec_s_enc.push_back(s);
	}

	return vec_s_enc;
}

shared_ptr<GroupElement> Sensor::check_key(vector<shared_ptr<GroupElement>> vec_B, shared_ptr<SymmetricCiphertext> aes_K) {
	auto g = dlog->getGenerator();

	auto result = dlog->exponentiate(g.get(), 0); //initiate result with g^0 = 1

	for(int i=0; i<vec_B.size(); i++) {
		vector<unsigned char> B_i_bytes = dlog->decodeGroupElementToByteArray(vec_B[i].get());
		pad(B_i_bytes, 128);

		SecretKey aes_B_i_sk = SecretKey(B_i_bytes, "");
		aes_enc->setKey(aes_B_i_sk);

		shared_ptr<Plaintext> decryption = aes_enc->decrypt(aes_K.get());
		biginteger decryption_int = byte_to_int(((ByteArrayPlaintext *)decryption.get())->getText());

		cout << "decryption_int: " << decryption_int << endl;
		cout << "B_" << i << ": " << ((OpenSSLZpSafePrimeElement *)vec_B[i].get())->getElementValue() << endl;

		if(decryption_int == 1) {
			result = vec_B[i];
			break;
		}
	}

	return result;
}

//Add up all scores contained in vec_s_enc
shared_ptr<AsymmetricCiphertext> Sensor::add_scores(vector<shared_ptr<AsymmetricCiphertext>> vec_s_enc) {
	//%TODO add 0 for randomization
	shared_ptr<AsymmetricCiphertext> result = vec_s_enc[0];

	for(int i=1; i<vec_s_enc.size(); i++) {
		result = elgamal->multiply(result.get(), vec_s_enc[i].get());
	}

	/*shared_ptr<Plaintext> plaintext = elgamal->decrypt(result.get());
	cout << "Added scores: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)plaintext.get())->getElement()).get())->getElementValue() << endl;

	auto g = dlog->getGenerator();

	for(int i=0; i<30; i++) {
		auto gi = dlog->exponentiate(g.get(), i);
		cout << "i= " << i << ", g^i= " << ((OpenSSLZpSafePrimeElement *)gi.get())->getElementValue() << endl;
	}*/

	return result;
}

vector<shared_ptr<GroupElement>> Sensor::decrypt_vec_B_enc2(vector<shared_ptr<AsymmetricCiphertext>> vec_B_enc2) {
	vector<shared_ptr<GroupElement>> vec_B;

	for(int i=0; i<vec_B_enc2.size(); i++) {
		shared_ptr<Plaintext> plaintext = elgamal->decrypt(vec_B_enc2[i].get());
		shared_ptr<GroupElement> B_i = ((GroupElementPlaintext*)plaintext.get())->getElement();
		vec_B.push_back(B_i);
		cout << "B_" << i << ": " << ((OpenSSLZpSafePrimeElement *)B_i.get())->getElementValue() << endl;
	}

	return vec_B;
}

void Sensor::test_k_enc2(shared_ptr<AsymmetricCiphertext> k_enc) {
	shared_ptr<Plaintext> plaintext = elgamal->decrypt(k_enc.get());
	cout << "decrypted [k]: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)plaintext.get())->getElement()).get())->getElementValue() << endl;
}

shared_ptr<AsymmetricCiphertext> Sensor::test_S_enc(biginteger S) {
	auto g = dlog->getGenerator();
	auto g_S = dlog->exponentiate(g.get(), S);

  GroupElementPlaintext p1(g_S);
	shared_ptr<AsymmetricCiphertext> cipher = elgamal->encrypt(make_shared<GroupElementPlaintext>(p1));

	return cipher;
}

void Sensor::test_look_up() {
	auto g = dlog->getGenerator();

	Template T;
	T.print();

	shared_ptr<Template_enc> T_enc = encrypt_template(T);

	vector<int> vec_p = {0, 0, 0};

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

vector<shared_ptr<AsymmetricCiphertext>> Sensor::encrypt_scores(int nr) {
	vector<shared_ptr<AsymmetricCiphertext>> result;

	auto g = dlog->getGenerator();

	biginteger total_nr = 0;

	for(int i=0; i<nr; i++) {

		// create a random exponent r
		auto gen = get_seeded_prg();
		biginteger r = getRandomInRange(0, 0, gen.get());

		total_nr+=r;

		auto g1 = dlog->exponentiate(g.get(), r);

		GroupElementPlaintext p1(g1);

		shared_ptr<AsymmetricCiphertext> cipher = elgamal->encrypt(make_shared<GroupElementPlaintext>(p1));

		result.push_back(cipher);

		cout << "value " << i << ":          " << r << endl;
	}


	shared_ptr<AsymmetricCiphertext> g_total1 = result[0];

	for(int i=1; i<nr; i++) {
		g_total1 = elgamal->multiply(g_total1.get(), result[i].get());
	}

	auto g_total2 = dlog->exponentiate(g.get(), total_nr);

	cout << "g^total:              " << ((OpenSSLZpSafePrimeElement *)g_total2.get())->getElementValue() << endl;

	return result;
}

int main_ss() {
	Sensor ss(make_shared<OpenSSLDlogZpSafePrime>(128));

	ss.capture(make_pair(3, 2));

	//ss.test_look_up();

	//ss.enroll();

	return 0;
}
