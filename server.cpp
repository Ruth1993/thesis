#include <iostream>
#include <vector>
#include <algorithm>
#include <stdlib.h>
#include <array>
#include <chrono>

#include "server.hpp"

using namespace std;

Server::Server(shared_ptr<OpenSSLDlogZpSafePrime> dlogg) {
	aes_enc = make_shared<OpenSSLCTREncRandomIV>("AES");

	dlog = dlogg;
	elgamal = make_shared<ElGamalOnGroupElementEnc>(dlog);

	auto key_pair = elgamal->generateKey();
	elgamal->setKey(key_pair.first, key_pair.second);
}

//add random table entry
void Server::store_table(tuple<int, shared_ptr<Template_enc>, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>>> enrollment) {
	table.add_entry(get<0>(enrollment), get<1>(enrollment), get<2>(enrollment).first, get<2>(enrollment).second);
}

shared_ptr<Template_enc> Server::fetch_template(int u) {
	return table.get_T_enc(u);
}

vector<shared_ptr<AsymmetricCiphertext>> Server::compare(shared_ptr<AsymmetricCiphertext> cap_s_enc, biginteger t, biginteger max_s) {
	biginteger max_S = 10*max_s;
	vector<shared_ptr<AsymmetricCiphertext>> vec_cap_c_enc;

	auto g = dlog->getGenerator();
	auto g_t = dlog->exponentiate(g.get(), t);

	//first compute and encrypt g^-t
	shared_ptr<GroupElement> g_min_t = dlog->getInverse(g_t.get());
	GroupElementPlaintext p_g_min_t(g_min_t);
  shared_ptr<AsymmetricCiphertext> c_g_min_t = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_g_min_t));

	//cout << "g^-t: " << ((OpenSSLZpSafePrimeElement *)g_min_t.get())->getElementValue() << endl;

	for(biginteger i=0; i<=max_S-t; i++) {
		//cout << "i: " << i << endl;

		//first compute and encrypt g^-i
		auto g_i = dlog->exponentiate(g.get(), i);
		shared_ptr<GroupElement> g_min_i = dlog->getInverse(g_i.get());
		//cout << "g^-i: " << ((OpenSSLZpSafePrimeElement *)g_min_i.get())->getElementValue() << endl;
		GroupElementPlaintext p_g_min_i(g_min_i);
	  shared_ptr<AsymmetricCiphertext> c_g_min_i = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_g_min_i));

		//multiply g^S * g^-t * g^-i = g^(S-t-i)
		shared_ptr<AsymmetricCiphertext> result = elgamal->multiply(cap_s_enc.get(), c_g_min_t.get());
		result = elgamal->multiply(result.get(), c_g_min_i.get());

		//save result in cap_c_enc
		vec_cap_c_enc.push_back(result);
	}

	return vec_cap_c_enc;
}

//Permute [[C]]
vector<shared_ptr<AsymmetricCiphertext>> Server::permute(vector<shared_ptr<AsymmetricCiphertext>> vec_cap_c_enc) {
	unsigned seed = chrono::system_clock::now().time_since_epoch().count();
	shuffle(vec_cap_c_enc.begin(), vec_cap_c_enc.end(), default_random_engine(seed));

	return vec_cap_c_enc;
}

pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> Server::fetch_key_pair(int u) {
	return table.get_key_pair(u);
}

vector<shared_ptr<AsymmetricCiphertext>> Server::potential_keys(vector<shared_ptr<AsymmetricCiphertext>> vec_cap_c_enc2, shared_ptr<AsymmetricCiphertext> cap_k_enc2) {
	vector<shared_ptr<AsymmetricCiphertext>> cap_b_enc2;

	cout << "inside function potential_keys, before loop" << endl;

	for(shared_ptr<AsymmetricCiphertext> cap_c_i_enc2 : vec_cap_c_enc2) {
		shared_ptr<AsymmetricCiphertext> cap_b_i_enc2 = elgamal->multiply(cap_c_i_enc2.get(), cap_k_enc2.get());
		cap_b_enc2.push_back(cap_b_i_enc2);
		cout << "[B].size = " << cap_b_enc2.size() << endl;
	}

	return cap_b_enc2;
}

int Server::size_table() {
	return table.size();
}

void Server::test_potential_keys() {
	auto g = dlog->getGenerator();

	vector<shared_ptr<AsymmetricCiphertext>> vec;

	for(int i=0; i<3; i++) {
		auto x = dlog->exponentiate(g.get(), i);
  	GroupElementPlaintext p1(x);
		shared_ptr<AsymmetricCiphertext> cipher1 = elgamal->encrypt(make_shared<GroupElementPlaintext>(p1));
		vec.push_back(cipher1);
	}

	cout << "size of [C]: " << vec.size() << endl;

	auto K = dlog->exponentiate(g.get(), 5);
	GroupElementPlaintext p2(K);
	shared_ptr<AsymmetricCiphertext> cipher2 = elgamal->encrypt(make_shared<GroupElementPlaintext>(p2));

	vector<shared_ptr<AsymmetricCiphertext>> keys = potential_keys(vec, cipher2);

	cout << "size of [B]: " << keys.size() << endl;
}

//Compare S with threshold t
void Server::test_compare(biginteger t, biginteger max_s) {
	auto g = dlog->getGenerator();

	cout << "t: " << t << endl;
	cout << "max_s: " << max_s << endl << endl;

	for(int i=0; i<10; i++) {
		cout << "S: " << i << endl;

		biginteger cap_s = i;

		auto g_cap_s = dlog->exponentiate(g.get(), cap_s);
		GroupElementPlaintext p_g_cap_s(g_cap_s);
		shared_ptr<AsymmetricCiphertext> c_g_cap_s = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_g_cap_s));

		vector<shared_ptr<AsymmetricCiphertext>> vec_cap_c_enc = compare(c_g_cap_s, t, max_s);

		//test if there's a C_i that equals 1 when decrypted
		for(shared_ptr<AsymmetricCiphertext> cap_c_i_enc : vec_cap_c_enc) {
			shared_ptr<Plaintext> cap_c_i = elgamal->decrypt(cap_c_i_enc.get());
			cout << "C_i: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)cap_c_i.get())->getElement()).get())->getElementValue() << endl;
		}

		cout << endl;
	}
}

//Permute order of comparison vector
void Server::test_permute(biginteger cap_s, biginteger t, biginteger max_s) {
	auto g = dlog->getGenerator();

	auto g_cap_s = dlog->exponentiate(g.get(), cap_s);
	GroupElementPlaintext p_g_cap_s(g_cap_s);
	shared_ptr<AsymmetricCiphertext> c_g_cap_s = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_g_cap_s));

	vector<shared_ptr<AsymmetricCiphertext>> vec_cap_c_enc = compare(c_g_cap_s, t, max_s);

	//print all C_i
	for(shared_ptr<AsymmetricCiphertext> cap_c_i_enc : vec_cap_c_enc) {
		shared_ptr<Plaintext> cap_c_i = elgamal->decrypt(cap_c_i_enc.get());
		cout << "C_i: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)cap_c_i.get())->getElement()).get())->getElementValue() << endl;
	}

	cout << endl;

	vector<shared_ptr<AsymmetricCiphertext>> vec_cap_c_enc_prime = permute(vec_cap_c_enc);

	//print all C_i when [[C]] has been permuted
	for(shared_ptr<AsymmetricCiphertext> cap_c_i_enc_prime : vec_cap_c_enc_prime) {
		shared_ptr<Plaintext> cap_c_i_prime = elgamal->decrypt(cap_c_i_enc_prime.get());
		cout << "C_i': " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)cap_c_i_prime.get())->getElement()).get())->getElementValue() << endl;
	}
}

int main_sv() {
	Server sv(make_shared<OpenSSLDlogZpSafePrime>(128));

	sv.test_potential_keys();

	return 0;
}
