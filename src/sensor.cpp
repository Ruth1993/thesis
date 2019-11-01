/*
*	Created using libscapi (see https://crypto.biu.ac.il/SCAPI/)
*	Authors: Ruth Scholten
*/

#include <iostream>
#include <array>
#include <chrono>
#include <random>
#include <stdlib.h>
#include <time.h>
#include <vector>

#include "../include/sensor.hpp"

using namespace std;

Sensor::Sensor() {
	//Initialize encryption objects
	aes = make_shared<OpenSSLCTREncRandomIV>("AES");

	dlog = make_shared<OpenSSLDlogECF2m>("../../libscapi/include/configFiles/NISTEC.txt", "K-233");
	//dlog = make_shared<OpenSSLDlogECFp>("B-163");
	elgamal = make_shared<ElGamalOnGroupElementEnc>(dlog);

	//Generate ElGamal keypair
	auto start = std::chrono::high_resolution_clock::now();

	auto pair = elgamal->generateKey();

	pk_own = pair.first;
	sk_own = pair.second;

	elgamal->setKey(pk_own, sk_own);
	auto end = std::chrono::high_resolution_clock::now();

	cout << "ElGamal setup: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << endl;
}

/*
*	Captures vec_p with identity claim u
*/
pair<int, vector<int>> Sensor::capture(int u, pair<int, int> template_size) {
	vector<int> vec_p;

	int len = template_size.second;

	cout << "capture():		u: " << u << "		vec(p): ";

	for(int i=0; i<template_size.first; i++) {
		unsigned seed = chrono::system_clock::now().time_since_epoch().count();
		srand(seed);
		vec_p.push_back(rand()%len);
		//vec_p.push_back(i);
		cout << vec_p[i] << ", ";
	}

	cout << endl;

	return make_pair(u, vec_p);
}

/*
*	Captures vec_p with random identity claim u
*/
pair<int, vector<int>> Sensor::capture(pair<int, int> template_size) {
	unsigned seed = chrono::system_clock::now().time_since_epoch().count();
	srand(seed);
	int u = rand();
	cout << "capture(): u= " << u << endl;

	capture(u, template_size);
}

/*
*	Encrypt template using ElGamal
*/
shared_ptr<Template_enc> Sensor::encrypt_template(Template T) {
	Template_enc T_enc;

	auto g = dlog->getGenerator();

	for(vector<biginteger> Col : T.T) {
		vector<shared_ptr<AsymmetricCiphertext>> Col_enc;

		for(biginteger s : Col) {
			//first encode s_{i,j} as g^s_{i,j}
			auto s_prime = dlog->exponentiate(g.get(), s);

			GroupElementPlaintext p(s_prime);
			shared_ptr<AsymmetricCiphertext> cipher = elgamal->encrypt(make_shared<GroupElementPlaintext>(p));

			Col_enc.push_back(cipher);
		}

		T_enc.add_col(Col_enc);
	}

	return make_shared<Template_enc>(T_enc);
}

shared_ptr<Template> Sensor::decrypt_template(shared_ptr<Template_enc> T_enc) {
	pair<int, int> size = T_enc->size();

	Template T(size, 0, 0);

	for(int i=0; i<size.first; i++) {
		for(int j=0; j<size.second; j++) {
			shared_ptr<AsymmetricCiphertext> s_enc = T_enc->get_elem(i, j);
			shared_ptr<Plaintext> p_s = elgamal->decrypt(s_enc.get());
			biginteger s = ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)p_s.get())->getElement()).get())->getElementValue();

			T.set_elem(s, i, j);
		}
	}

	return make_shared<Template>(T);
}

/*
*	Enrollment procedure (Steps 1-6)
*/
tuple<int, shared_ptr<Template_enc>, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>>> Sensor::enroll(int u, pair<int, int> template_size, int min_s, int max_s) {
	auto g = dlog->getGenerator();

	//Step 2 Construct Template_enc
	Template T(template_size, min_s, max_s); //In real life settings T, is constructed from a captured biometric identifier, but for simplicity purposes we generate it randomly
	T.print();

	//Step 3 Encrypt template T
	shared_ptr<Template_enc> T_enc = encrypt_template(T);

	//Step 4: pick k \in_R [0, |G|]
	biginteger q = dlog->getOrder();
	auto gen = get_seeded_prg();
	biginteger k = getRandomInRange(0, q-1, gen.get()); //generate random k

	//First encode k to g^k
	//also we need to do mod(g^k, 2^129-1) because AES supports only key sizes of 128/192/256 bits
	auto g_k = dlog->exponentiate(g.get(), k);
	//biginteger g_k_mod = mod((ZpElement*)g_k->getElementValue(), pow(2, 129) - 1);

	//Step 5: encrypt g_k, but first set pk to pk_shared
	elgamal->setKey(pk_shared);
	GroupElementPlaintext p_k(g_k);
	shared_ptr<AsymmetricCiphertext> k_enc = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_k));

	//Step 6: aes_k_1(1)
	//First copy g_k to byte vector in order to use in AES encryption
	vector<byte> g_k_vec = dlog->decodeGroupElementToByteArray(g_k.get());

	//then hash K
	shared_ptr<CryptographicHash> H = make_shared<OpenSSLSHA256>();
	H->update(g_k_vec, 0, g_k_vec.size());
	vector<byte> g_k_hash;
	H->hashFinal(g_k_hash, 0);

	//Pad byte vector of g^k (mod 2^129-1) to get byte vector of 128 bits
	//pad(g_k_hash, 128);

	//vector<byte> g_k_hash;

	//gen_random_bytes_vector(g_k_hash, 16, get_seeded_prg().get());

	//byte arr_k[15];
	//copy_byte_vector_to_byte_array(vec_k, &arr_k, 0);
	//print_byte_array(arr_k, vec_k.size(), "");
	SecretKey aes_k_sk = SecretKey(g_k_hash, "");

	aes->setKey(aes_k_sk);

	vector<unsigned char> vec = int_to_byte(1);
	ByteArrayPlaintext p1(vec);

	shared_ptr<SymmetricCiphertext> aes_k_1 = aes->encrypt(&p1);
	/*shared_ptr<Plaintext> decryption = aes->decrypt(aes_k_1.get());
	biginteger decryption_int = byte_to_int(((ByteArrayPlaintext*)decryption.get())->getText());

	cout << "decryption_int: " << decryption_int << endl;*/


	return make_tuple(u, T_enc, make_pair(k_enc, aes_k_1));
}

/*
*	Look up similarity scores in T_u by selecting the corresponding rows using vec_p
*	assert vec_p.size() == T_enc.T_enc.size()
*	assert \forall p in vec_p: 0 <= p < col
*/
vector<shared_ptr<AsymmetricCiphertext>> Sensor::look_up(vector<int> vec_p, shared_ptr<Template_enc> T_enc) {
	vector<shared_ptr<AsymmetricCiphertext>> vec_s_enc;

	for(int i=0; i<T_enc->size().first; i++) {
		shared_ptr<AsymmetricCiphertext> s = T_enc->get_elem(i, vec_p[i]);

		vec_s_enc.push_back(s);
	}

	return vec_s_enc;
}

/*
*	Add up all scores contained in [[vec_s]]
*/
shared_ptr<AsymmetricCiphertext> Sensor::add_scores(vector<shared_ptr<AsymmetricCiphertext>> vec_s_enc) {
	//first add 0 (g^0) for randomization
	auto g = dlog->getGenerator();
	auto id = dlog->exponentiate(g.get(), 0);
	GroupElementPlaintext p_id(id);
	shared_ptr<AsymmetricCiphertext> c_id = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_id));

	shared_ptr<AsymmetricCiphertext> result = c_id;

	for(int i=0; i<vec_s_enc.size(); i++) {
		result = elgamal->multiply(result.get(), vec_s_enc[i].get());
	}

	return result;
}

bool Sensor::verify_permutation2(vector<shared_ptr<AsymmetricCiphertext>> C_enc, vector<shared_ptr<AsymmetricCiphertext>> C_enc_prime) {
	auto g = dlog->getGenerator();
	//cout << "g: " << ((OpenSSLZpSafePrimeElement*)g.get())->getElementValue() << endl;
	biginteger q = dlog->getOrder();
	//cout << "q: " << q << endl;
	auto gen = get_seeded_prg();

	int k = C_enc_prime.size();
	int k5 = k + 5;

	//cout << "before loop f_u" << endl;

	//Generate F_k \in_R Z_q for k=-4,...,k
	vector<shared_ptr<GroupElement>> f(k+5, 0);
	for (int micro = 0; micro < k5; micro++) {
		f[micro] = dlog->createRandomElement();
	}

	//Send F_k to prover
	send_vec_group_element(f);

	//cout << "before receive commitment" << endl;

	//Receive commitment from prover
	auto g_0_prime = recv_group_element();
	auto m_0_prime = recv_group_element();
	auto f_tilde_0_prime = recv_group_element();
	vector<shared_ptr<GroupElement>> f_prime = recv_vec_group_element();
	biginteger w = recv_biginteger();
	biginteger w_dot = recv_biginteger();

	//cout << "before challenge" << endl;

	//Pick random challenge c_i \in Z_q for i=1,...,k
	vector<biginteger> c(k+1, 0);
	c[0] = 1;

	for (int i = 1; i < k+1; i++) {
		c[i] = getRandomInRange(10, 20, gen.get());
	}

	//Send challenge to the prover
	send_vec_biginteger(c);

	//cout << "before receive response" << endl;

	//Receive response from prover
	vector<biginteger> r = recv_vec_biginteger();
	vector<biginteger> r_prime = recv_vec_biginteger();

	//cout << "before verify 9" << endl;

	//Verify following statements (in paper Furukawa statements 9-13)
	biginteger alpha = getRandomInRange(0, q - 1, gen.get());

	auto left9 = dlog->getIdentity();
	auto right9 = dlog->multiplyGroupElements(f_prime[0].get(), dlog->exponentiate(f_tilde_0_prime.get(), alpha).get());

	//cout << "before loop 9" << endl;

	for (int v = 0; v < k+5; v++) {
		left9 = dlog->multiplyGroupElements(left9.get(), dlog->exponentiate(f[v].get(), mod(r[v]+alpha*r_prime[v], q)).get());
	}

	//cout << "before right9" << endl;

	for (int i = 0; i < k; i++) {
		right9 = dlog->multiplyGroupElements(right9.get(), dlog->exponentiate(f_prime[i + 1].get(), mod(c[i + 1] + alpha * c[i + 1] * c[i + 1], q)).get());
	}

	//cout << "before verify 10 and 11" << endl;

	auto left10 = dlog->exponentiate(g.get(), r[0+4]);
	auto right10 = dlog->exponentiate(g_0_prime.get(), c[0]);

	auto left11 = dlog->exponentiate(g.get(), r[0+4]);
	auto right11 = dlog->exponentiate(m_0_prime.get(), c[0]);

	for (int v = 0; v < k; v++) {
		auto g_v = ((ElGamalOnGroupElementCiphertext*)C_enc[v].get())->getC1();
		auto m_v = ((ElGamalOnGroupElementCiphertext*)C_enc[v].get())->getC2();

		auto g_micro_prime = ((ElGamalOnGroupElementCiphertext*)C_enc_prime[v].get())->getC1();
		auto m_micro_prime = ((ElGamalOnGroupElementCiphertext*)C_enc_prime[v].get())->getC2();

		cout << "r[" << (v+5) << "]: " << r[v + 5] << endl << endl;
		cout << "c[" << (v + 1) << "]: " << c[v + 1] << endl << endl;

		auto left10_test = dlog->exponentiate(g_v.get(), r[v + 5]);
		auto right10_test = dlog->exponentiate(g_micro_prime.get(), c[v + 1]);
		left10 = dlog->multiplyGroupElements(left10.get(), left10_test.get());
		right10 = dlog->multiplyGroupElements(right10.get(), right10_test.get());

		cout << "left10[" << v << "]:" << ((OpenSSLZpSafePrimeElement*)left10_test.get())->getElementValue() << endl;
		cout << "right10[" << v << "]:" << ((OpenSSLZpSafePrimeElement*)right10_test.get())->getElementValue() << endl;

		left11 = dlog->multiplyGroupElements(left11.get(), dlog->exponentiate(m_v.get(), r[v+5]).get());
		right11 = dlog->multiplyGroupElements(right11.get(), dlog->exponentiate(m_micro_prime.get(), c[v+1]).get());
	}

	//cout << "before verify 12 and 13" << endl;

	biginteger left12;
	biginteger right12 = mod(r[-2 + 4] + r_prime[-3+4]+w, q);

	biginteger left13;
	biginteger right13 = mod(r[-4 + 4] + w_dot, q);

	for (int j = 0; j < k; j++) {
		left12 += mod(r[j+5] * r[j+5] * r[j+5] - c[j+1]*c[j+1]*c[j+1], q);
		left13 += mod(r[j+5] * r[j+5] - c[j+1] * c[j+1], q);
	}

	cout << "left13: " << left13 << endl;
	cout << "right13: " << right13 << endl;

	return (*left10.get() == *right10.get());
	//return (*left9.get() == *right9.get()) && (*left10.get() == *right10.get()) && (*left11.get() == *right11.get()) && (left12 == right12) && (left13 == right13);
}

/*
*	Verify correctness of permutation function \pi
*/
bool Sensor::verify_permutation(vector<shared_ptr<AsymmetricCiphertext>> C_enc, vector<shared_ptr<AsymmetricCiphertext>> C_enc_prime) {
	auto g = dlog->getGenerator();
	biginteger q = dlog->getOrder();
	auto gen = get_seeded_prg();

	//Receive \tilde{g} and {\tilde_i} from the prover
	auto g_tilde = recv_group_element();
	vector<shared_ptr<GroupElement>> vec_g_tilde = recv_vec_group_element();

	//Receive parameters from prover
	auto t = recv_group_element();
	auto v = recv_group_element();
	auto w = recv_group_element();
	auto u = recv_group_element();
	vector<shared_ptr<GroupElement>> vec_u = recv_vec_group_element();
	vector<shared_ptr<GroupElement>> vec_g_tilde_prime = recv_vec_group_element();
	auto g_tilde_prime = recv_group_element();
	auto g_prime = recv_group_element();
	auto m_prime = recv_group_element();
	vector<shared_ptr<GroupElement>> vec_t_dot = recv_vec_group_element();
	vector<shared_ptr<GroupElement>> vec_v_dot = recv_vec_group_element();
	auto v_dot = recv_group_element();
	vector<shared_ptr<GroupElement>> vec_w_dot = recv_vec_group_element();
	auto w_dot = recv_group_element();

	int n = vec_u.size();

	//Compute challenges c_i for 0 <= i < n
	vector<biginteger> c;

	for (int i = 0; i < n; i++) {
		c.push_back(getRandomInRange(0, q - 1, gen.get()));
	}

	//Send challenges to prover
	send_vec_biginteger(c);

	//Receive s, s_i and \lambda' from prover
	biginteger s = recv_biginteger();
	vector<biginteger> vec_s = recv_vec_biginteger();
	biginteger lambda_prime = recv_biginteger();

	//Verify following statements (in paper Furukawa statements 11-16)
	auto left11 = dlog->exponentiate(g_tilde.get(), s);
	auto right11 = g_tilde_prime;

	auto left12 = dlog->exponentiate(g.get(), s);
	auto right12 = g_prime;

	auto left13 = dlog->exponentiate(((ElGamalPublicKey*) pk_shared.get())->getH().get(), s);
	auto right13 = m_prime;

	auto left14 = dlog->exponentiate(g.get(), lambda_prime);
	auto right14 = u;

	auto left15 = dlog->multiplyGroupElements(dlog->exponentiate(t.get(), lambda_prime).get(), dlog->exponentiate(v.get(), s).get());
	auto right15 = v_dot;

	auto left16 = dlog->exponentiate(w.get(), s);
	auto right16 = w_dot;

	for (int j = 0; j < n; j++) {
		auto g_j = ((ElGamalOnGroupElementCiphertext*) C_enc[j].get())->getC1();
		auto g_j_prime = ((ElGamalOnGroupElementCiphertext*) C_enc_prime[j].get())->getC1();
		auto m_j = ((ElGamalOnGroupElementCiphertext*) C_enc[j].get())->getC2();
		auto m_j_prime = ((ElGamalOnGroupElementCiphertext*) C_enc_prime[j].get())->getC2();

		left11 = dlog->multiplyGroupElements(left11.get(), dlog->exponentiate(vec_g_tilde[j].get(), vec_s[j]).get());
		right11 = dlog->multiplyGroupElements(right11.get(), dlog->exponentiate(vec_g_tilde_prime[j].get(), c[j]).get());

		left12 = dlog->multiplyGroupElements(left12.get(), dlog->exponentiate(g_j.get(), vec_s[j]).get());
		right12 = dlog->multiplyGroupElements(right12.get(), dlog->exponentiate(g_j_prime.get(), c[j]).get());

		left13 = dlog->multiplyGroupElements(left13.get(), dlog->exponentiate(m_j.get(), vec_s[j]).get());
		right13 = dlog->multiplyGroupElements(right13.get(), dlog->exponentiate(m_j_prime.get(), c[j]).get());

		right14 = dlog->multiplyGroupElements(right14.get(), dlog->exponentiate(vec_u[j].get(), mod(c[j]*c[j], q)).get());

		left15 = dlog->multiplyGroupElements(left15.get(), dlog->exponentiate(g.get(), mod(vec_s[j]*vec_s[j]*vec_s[j] - c[j]*c[j]*c[j], q)).get());
		right15 = dlog->multiplyGroupElements(right15.get(), dlog->multiplyGroupElements(dlog->exponentiate(vec_v_dot[j].get(), c[j]).get(), dlog->exponentiate(vec_t_dot[j].get(), mod(c[j] * c[j], q)).get()).get());

		left16 = dlog->multiplyGroupElements(left16.get(), dlog->exponentiate(g.get(), mod(vec_s[j] * vec_s[j] - c[j] * c[j], q)).get());
		right16 = dlog->multiplyGroupElements(right16.get(), dlog->exponentiate(vec_w_dot[j].get(), c[j]).get());
	}
	
	return (*left11.get() == *right11.get()) && (*left12.get() == *right12.get()) && (*left13.get() == *right13.get()) && (*left14.get() == *right14.get()) && (*left15.get() == *right15.get()) && (*left16.get() == *right16.get());
}

/*
*	Decrypt all the values in [B]
*/
vector<shared_ptr<GroupElement>> Sensor::decrypt_B_enc2(vector<shared_ptr<AsymmetricCiphertext>> B_enc2) {
	vector<shared_ptr<GroupElement>> B;

	for(int i=0; i<B_enc2.size(); i++) {
		shared_ptr<Plaintext> plaintext = elgamal->decrypt(B_enc2[i].get());
		shared_ptr<GroupElement> B_i = ((GroupElementPlaintext*)plaintext.get())->getElement();
		B.push_back(B_i);
		//cout << "B_" << i << ": " << ((OpenSSLZpSafePrimeElement *)B_i.get())->getElementValue() << endl;
	}

	return B;
}

/*
*	For every value in B, check if AES_{B_i} == 1. In case there is such a value, B_i is the key that is released by the system and can be used by the sensor device for further applications
*/
shared_ptr<GroupElement> Sensor::check_key(vector<shared_ptr<GroupElement>> B, shared_ptr<SymmetricCiphertext> aes_k_1) {
	shared_ptr<CryptographicHash> H = make_shared<OpenSSLSHA256>();
	auto g = dlog->getGenerator();

	auto result = dlog->exponentiate(g.get(), 0); //initiate result with g^0 = 1

	for(int i=0; i<B.size(); i++) {
		vector<unsigned char> B_i_bytes = dlog->decodeGroupElementToByteArray(B[i].get());

		//pad(B_i_bytes, 128);

		H->update(B_i_bytes, 0, B_i_bytes.size());
		vector<byte> B_i_hash;
		H->hashFinal(B_i_hash, 0);

		SecretKey aes_B_i_sk = SecretKey(B_i_hash, "");
		aes->setKey(aes_B_i_sk);

		shared_ptr<Plaintext> decryption = aes->decrypt(aes_k_1.get());
		biginteger decryption_int = byte_to_int(((ByteArrayPlaintext *)decryption.get())->getText());

		//cout << "B_" << i << ": " << ((OpenSSLZpSafePrimeElement *)B[i].get())->getElementValue() << endl;

		if(decryption_int == 1) {
			result = B[i];
			break;
		}
	}

	return result;
}

/*
*	Test function lookup
*/
void Sensor::test_look_up() {
	auto g = dlog->getGenerator();

	Template T(template_size, min_s, max_s);
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

/*
*	Test function test_add_scores
*/
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

/*
*	Print outcomes of g^i for 0 <= total < 30
*/
void Sensor::print_outcomes(int total) {
	auto g = dlog->getGenerator();

	for(int i=0; i<total; i++) {
			auto h = dlog->exponentiate(g.get(), i);
				cout << "g^" << i << ": " << ((OpenSSLZpSafePrimeElement *)h.get())->getElementValue() << endl;
	}
}

/*
*	Show usage of the program
*/
int Sensor::usage() {
	cout << "Usage: " << endl;
	cout << "*	Semi-honest protocol with key release: ./sensor | ./sensor sh" << endl;
	cout << "*	Malicious protocol with key release: ./sensor mal" << endl;

	return 0;
}

/*
*	Main function for semi-honest protocol
*/
int Sensor::main_sh() {
	try {
		//First set up channel
		boost::asio::io_service io_service;

		SocketPartyData server = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8000);
		SocketPartyData sensor = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8001);

		channel = make_shared<CommPartyTCPSynced>(io_service, sensor, server);

		boost::thread th(boost::bind(&boost::asio::io_service::run, &io_service));

		//Join channel
		channel->join(500, 5000);
		cout << "channel established" << endl;

		//Receive public key from server
		shared_ptr<PublicKey> pk_sv = recv_pk();

		//Send own public key to Server
		send_pk();

		//Set shared public key
		key_setup(pk_sv);

		//Create enrollment parameters and send to server
		int u_enroll = 1;
		tuple<int, shared_ptr<Template_enc>, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>>> enrollment = enroll(u_enroll, template_size, min_s, max_s);
		send_msg(get<0>(enrollment)); //send u
		send_template(get<1>(enrollment)); //send template T_u
		send_msg_enc(get<2>(enrollment).first); //send [[k]]
		send_aes_msg(get<2>(enrollment).second); //send aes_k_1(1)

		//Capture (u, vec(p))
		pair<int, vector<int>> cap = capture(u_enroll, template_size);
		int u = cap.first;
		vector<int> vec_p = cap.second;

		//Send u to server
		send_msg(u);

		//Receive template T_u from server
		shared_ptr<Template_enc> T_enc = recv_template();

		//Lookup vec_p in [[T_u]] and add up partial similarity scores
		vector<shared_ptr<AsymmetricCiphertext>> vec_s_enc = look_up(vec_p, T_enc);
		shared_ptr<AsymmetricCiphertext> S_enc = add_scores(vec_s_enc);

		//Send [[S]] to server
		send_msg_enc(S_enc);

		//Receive pair ([B], aes_k_1(1)) from server
		vector<shared_ptr<AsymmetricCiphertext>> B_enc2 = recv_vec_enc();
		shared_ptr<SymmetricCiphertext> aes_k_1 = recv_aes_msg();

		//Fully decrypt [B] and check if it consists a valid key
		vector<shared_ptr<GroupElement>> B = decrypt_B_enc2(B_enc2);
		shared_ptr<GroupElement> key = check_key(B, aes_k_1);

		cout << "Key: " << ((OpenSSLZpSafePrimeElement*)key.get())->getElementValue() << endl;

		io_service.stop();
		th.join();
	} catch (const logic_error& e) {
			cerr << e.what();
	}

	return 0;
}

/*
*	Main function for malicious protocol
*/
int Sensor::main_mal() {
	try {
		//First set up channel
		boost::asio::io_service io_service;

		SocketPartyData server = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8000);
		SocketPartyData sensor = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8001);

		channel = make_shared<CommPartyTCPSynced>(io_service, sensor, server);

		boost::thread th(boost::bind(&boost::asio::io_service::run, &io_service));

		//Join channel
		channel->join(500, 5000);
		cout << "channel established" << endl;

		//Receive public key from server
		auto start_setup = std::chrono::high_resolution_clock::now();

		shared_ptr<PublicKey> pk_sv = recv_pk();

		//Send own public key to Server
		send_pk();

		//Set shared public key
		key_setup(pk_sv);

		auto end_setup = std::chrono::high_resolution_clock::now();

		//Create enrollment parameters
		int u_enroll = 1;

		auto start_enroll = std::chrono::high_resolution_clock::now();

		tuple<int, shared_ptr<Template_enc>, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>>> enrollment = enroll(u_enroll, template_size, min_s, max_s);

		auto end_enroll = std::chrono::high_resolution_clock::now();

		shared_ptr<Template_enc> T_enc_enroll = get<1>(enrollment);
		shared_ptr<AsymmetricCiphertext> k_enc_enroll = get<2>(enrollment).first;
		shared_ptr<SymmetricCiphertext> aes_k_enroll = get<2>(enrollment).second;

		//Create signature over m = (u, [[T_u]]) and n = (u, [[k]], aes_k_1(1))
		auto start_sig = std::chrono::high_resolution_clock::now();

		shared_ptr<Signer> signer = make_shared<Signer>();
		vector<byte> m_enroll = compute_m(u_enroll, T_enc_enroll);
		vector<byte> n_enroll = compute_n(u_enroll, k_enc_enroll, aes_k_enroll);
		Signature sig_m_enroll = signer->sign(m_enroll);
		Signature sig_n_enroll = signer->sign(n_enroll);

		auto end_sig = std::chrono::high_resolution_clock::now();

		//Send enrollment parameters m and n along with their signatures \sigma(m) and \sigma(n) to the server
		auto start_comm1 = std::chrono::high_resolution_clock::now();

		send_msg(u_enroll); //send u
		send_template(T_enc_enroll); //send template T_u
		send_msg_enc(k_enc_enroll); //send [[k]]
		send_aes_msg(aes_k_enroll); //send aes_k_1(1)
		send_signature(sig_m_enroll); //send \sigma(m)
		send_signature(sig_n_enroll); //send \sigma(n)
		send_group_element(signer->y); //send public key y

		cout << "y: " << ((OpenSSLZpSafePrimeElement*)signer->y.get())->getElementValue() << endl;

		auto end_comm1 = std::chrono::high_resolution_clock::now();

		//Capture (u, vec(p))
		auto start_capture = std::chrono::high_resolution_clock::now();

		pair<int, vector<int>> cap = capture(u_enroll, template_size);

		auto end_capture = std::chrono::high_resolution_clock::now();

		int u = cap.first;
		vector<int> vec_p = cap.second;

		//Send u to server
		auto start_comm2 = std::chrono::high_resolution_clock::now();

		send_msg(u);

		//Receive template T_u from server
		shared_ptr<Template_enc> T_enc = recv_template();
		shared_ptr<AsymmetricCiphertext> k_enc = recv_msg_enc();
		shared_ptr<SymmetricCiphertext> aes_k_1 = recv_aes_msg();
		Signature sig_m = recv_signature();
		Signature sig_n = recv_signature();
		shared_ptr<GroupElement> y = recv_group_element();

		auto end_comm2 = std::chrono::high_resolution_clock::now();

		//Verify [[T_u]] and key pair ([[k]], aes_k_1(1)) using \sigma(m) and \sigma(n), respectively
		auto start_ver_sig = std::chrono::high_resolution_clock::now();

		shared_ptr<Verifier> verifier = make_shared<Verifier>();
		vector<byte> m = compute_m(u, T_enc);
		vector<byte> n = compute_n(u, k_enc, aes_k_1);

		cout << "[[T_u]] verified: " << verifier->verify(m, sig_m, y) << endl;
		cout << "([[k]], AES_k(1)) verified: " << verifier->verify(n, sig_n, y) << endl;

		auto end_ver_sig = std::chrono::high_resolution_clock::now();

		//Lookup vec_p in [[T_u]] and add up partial similarity scores
		auto start_lookup = std::chrono::high_resolution_clock::now();

		vector<shared_ptr<AsymmetricCiphertext>> vec_s_enc = look_up(vec_p, T_enc);
		shared_ptr<AsymmetricCiphertext> S_enc = add_scores(vec_s_enc);

		auto end_lookup = std::chrono::high_resolution_clock::now();

		//Send [[S]] to server
		auto start_comm3 = std::chrono::high_resolution_clock::now();

		send_msg_enc(S_enc);

		auto end_comm3 = std::chrono::high_resolution_clock::now();

		cout << "----[[S]]---->" << endl;

		//Receive [[C]] and [[C']] from server
		auto start_comm4 = std::chrono::high_resolution_clock::now();

		vector<shared_ptr<AsymmetricCiphertext>> C_enc = recv_vec_enc();
		vector<shared_ptr<AsymmetricCiphertext>> C_enc_prime = recv_vec_enc();

		cout << "<----([[C]], [[C']])---" << endl;

		auto end_comm4 = std::chrono::high_resolution_clock::now();

		//Verify permutation \pi([[C]] = [[C']]
		auto start_ver_permute = std::chrono::high_resolution_clock::now();

		cout << "permutation verified: " << verify_permutation2(C_enc, C_enc_prime) << endl;

		auto end_ver_permute = std::chrono::high_resolution_clock::now();

		//Also compute [[B]] = [[C']] + [[k]] to check server's computation of [[B]]
		auto start_B = std::chrono::high_resolution_clock::now();

		vector<shared_ptr<AsymmetricCiphertext>> B_enc = calc_B_enc(C_enc_prime, k_enc);

		auto end_B = std::chrono::high_resolution_clock::now();

		//Receive [B] from server
		auto start_comm5 = std::chrono::high_resolution_clock::now();

		vector<shared_ptr<AsymmetricCiphertext>> B_enc2 = recv_vec_enc();

		auto end_comm5 = std::chrono::high_resolution_clock::now();

		//Engage in ZK-proof with server to check that [B] is a correct decryption of [[B]] under sk_sk
		//TODO don't forget to include the [[B]] that we computed previously here

		//Fully decrypt [B]
		auto start_dec = std::chrono::high_resolution_clock::now();

		vector<shared_ptr<GroupElement>> B = decrypt_B_enc2(B_enc2);

		auto end_dec = std::chrono::high_resolution_clock::now();

		//Check if one of the decryptions yields a valid key
		auto start_check = std::chrono::high_resolution_clock::now();

		shared_ptr<GroupElement> key = check_key(B, aes_k_1);

		auto end_check = std::chrono::high_resolution_clock::now();

		cout << "Key: " << ((OpenSSLZpSafePrimeElement*)key.get())->getElementValue() << endl;

		//Print elapsed time
		auto time_setup = chrono::duration_cast<chrono::microseconds>(end_setup - start_setup).count();
		auto time_enroll = chrono::duration_cast<chrono::microseconds>(end_enroll - start_enroll).count();
		auto time_sig = chrono::duration_cast<chrono::microseconds>(end_sig - start_sig).count();
		auto time_capture = chrono::duration_cast<chrono::microseconds>(end_capture - start_capture).count();
		auto time_ver_sig = chrono::duration_cast<chrono::microseconds>(end_ver_sig - start_ver_sig).count();
		auto time_lookup = chrono::duration_cast<chrono::microseconds>(end_lookup - start_lookup).count();
		auto time_ver_permute = chrono::duration_cast<chrono::microseconds>(end_ver_permute - start_ver_permute).count();
		auto time_dec = chrono::duration_cast<chrono::microseconds>(end_dec - start_dec).count();
		auto time_check = chrono::duration_cast<chrono::microseconds>(end_check - start_check).count();
		auto time_comm = chrono::duration_cast<chrono::microseconds>(end_comm1 - start_comm1 + end_comm2 - start_comm2 + end_comm3 - start_comm3 + end_comm4 - start_comm4 + end_comm5 - start_comm5).count();
		auto time_total = time_setup + time_enroll + time_sig + time_capture + time_ver_sig + time_lookup + time_ver_permute + time_dec + time_check + time_comm;

		cout << endl;
		cout << "Elapsed time in us: " << endl;
		cout << "Shared key setup: " << time_setup << endl;
		cout << "Create enrollment: " << time_enroll << endl;
		cout << "Signature verification: " << time_sig << endl;
		cout << "Capture: " << time_capture << endl;
		cout << "Verification signatures: " << time_ver_sig << endl;
		cout << "Lookup: " << time_lookup << endl;
		cout << "Verify permutation: " << time_ver_permute << endl;
		cout << "Decryption of [B]: " << time_dec << endl;
		cout << "Key check: " << time_check << endl;
		cout << "Total communication overhead: " << time_comm << endl;
		cout << endl;
		cout << "Total elapsed time in us: " << time_total << endl;
		cout << "Percentage verify permutation / total server: " << (double) time_ver_permute / time_total << endl;
		
		io_service.stop();
		th.join();
	}
	catch (const logic_error& e) {
		cerr << e.what();
	}

	return 0;
}

/*
*	General main function
*/
int main(int argc, char* argv[]) {
	Sensor ss = Sensor();

	if(argc == 1) {
		return ss.main_sh();
	} else if(argc == 2) {
	string arg(argv[1]);
		if(arg == "sh") {
			return ss.main_sh();
		} else if(arg == "mal") {
			return ss.main_mal();
		}
	} else {
		return ss.usage();
	}

	return 0;
}
