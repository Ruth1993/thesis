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
void Server::store_table() {

}

shared_ptr<Template_enc> Server::fetch_table() {

}

vector<shared_ptr<AsymmetricCiphertext>> Server::compare(shared_ptr<AsymmetricCiphertext> cap_s_enc, biginteger t, biginteger max_s) {
	vector<shared_ptr<AsymmetricCiphertext>> vec_cap_c_enc;

	auto g = dlog->getGenerator();
	auto g_t = dlog->exponentiate(g.get(), t);

	//first compute and encrypt g^-t
	shared_ptr<GroupElement> g_min_t = dlog->getInverse(g_t.get());
	GroupElementPlaintext p_g_min_t(g_min_t);
  shared_ptr<AsymmetricCiphertext> c_g_min_t = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_g_min_t));

	//cout << "g^-t: " << ((OpenSSLZpSafePrimeElement *)g_min_t.get())->getElementValue() << endl;

	for(biginteger i=0; i<=max_s-t; i++) {
		//cout << "i: " << i << endl;

		//first compute and encrypt g^-i
		auto g_i = dlog->exponentiate(g.get(), i);
		shared_ptr<GroupElement> g_min_i = dlog->getInverse(g_i.get());
		//cout << "g^-i: " << ((OpenSSLZpSafePrimeElement *)g_min_i.get())->getElementValue() << endl;
		GroupElementPlaintext p_g_min_i(g_min_i);
	  shared_ptr<AsymmetricCiphertext> c_g_min_i = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_g_min_i));

		//multiply g^S * g^-t * g^-i = g^(S-t-i)
		shared_ptr<AsymmetricCiphertext> result = elgamal->multiply(cap_s_enc.get(), c_g_min_t.get());;
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

int main() {
	Server sv(make_shared<OpenSSLDlogZpSafePrime>(128));

	sv.test_permute(5, 3, 10);

	return 0;
}
