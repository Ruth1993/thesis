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

	auto g = dlog->getGenerator();
	biginteger q = dlog->getOrder();
}

shared_ptr<PublicKey> Server::key_gen() {
	auto pair = elgamal->generateKey();

	shared_ptr<PublicKey> pk_sv = pair.first;
	sk_sv = pair.second;

	elgamal->setKey(pk_sv, sk_sv);

	return pk_sv;
}

void Server::key_setup(shared_ptr<PublicKey> pk_ss) {
	shared_ptr<GroupElement> h_shared = dlog->exponentiate(((ElGamalPublicKey*) pk_ss.get())->getH().get(), ((ElGamalPrivateKey*) sk_sv.get())->getX());

	cout << "h_shared for server: " << ((OpenSSLZpSafePrimeElement *)h_shared.get())->getElementValue() << endl;
	pk_shared = make_shared<ElGamalPublicKey>(ElGamalPublicKey(h_shared));

	elgamal->setKey(pk_shared);
}

shared_ptr<ElGamalOnGroupElementCiphertext> Server::test_partial_decrypt(shared_ptr<AsymmetricCiphertext> cipher) {
	shared_ptr<GroupElement> c_1_prime = dlog->exponentiate(((ElGamalOnGroupElementCiphertext*) cipher.get())->getC1().get(), ((ElGamalPrivateKey*) sk_sv.get())->getX());
	return make_shared<ElGamalOnGroupElementCiphertext>(ElGamalOnGroupElementCiphertext(c_1_prime, ((ElGamalOnGroupElementCiphertext*) cipher.get())->getC2()));
}

//add random table entry
void Server::store_table(tuple<int, shared_ptr<Template_enc>, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>>> enrollment) {
	table.add_entry(get<0>(enrollment), get<1>(enrollment), get<2>(enrollment).first, get<2>(enrollment).second);
}

shared_ptr<Template_enc> Server::fetch_template(int u) {
	cout << "size of table: " << table.size() << endl;
	return table.get_T_enc(u);
}

vector<shared_ptr<AsymmetricCiphertext>> Server::compare(shared_ptr<AsymmetricCiphertext> S_enc, biginteger t, biginteger max_S) {
	vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc;

	elgamal->setKey(pk_shared);

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
		shared_ptr<AsymmetricCiphertext> result = elgamal->multiply(S_enc.get(), c_g_min_t.get());
		result = elgamal->multiply(result.get(), c_g_min_i.get());

		//save result in C_enc
		vec_C_enc.push_back(result);
	}

	return vec_C_enc;
}

//Permute [[C]]
vector<shared_ptr<AsymmetricCiphertext>> Server::permute(vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc) {
	unsigned seed = chrono::system_clock::now().time_since_epoch().count();
	shuffle(vec_C_enc.begin(), vec_C_enc.end(), default_random_engine(seed));

	return vec_C_enc;
}


//Perform decryption step D1
vector<shared_ptr<AsymmetricCiphertext>> Server::D1(vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc) {
	vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc2;

	for(shared_ptr<AsymmetricCiphertext> C_i_enc : vec_C_enc) {
		//((ElGamalPublicKey*) pk_ss.get())->getH().get()
		//((ElGamalOnGroupElementCiphertext) C_i_enc.get())->getC2()
		//shared_ptr<GroupElement> c1_prime = dlog->exponentiate(((ElGamalOnGroupElementCiphertext*) C_i_enc.get())->getC1().get(), ((ElGamalPrivateKey*) sk_sv.get())->getX());
		//vec_C_enc2.push_back(ElGamalOnGroupElementCiphertext(c1_prime, ((ElGamalOnGroupElementCiphertext*) C_i_enc.get())->getC2()));

		shared_ptr<GroupElement> c1_prime = dlog->exponentiate(((ElGamalOnGroupElementCiphertext*) C_i_enc.get())->getC1().get(), ((ElGamalPrivateKey*) sk_sv.get())->getX());
		ElGamalOnGroupElementCiphertext C_i_enc2 = ElGamalOnGroupElementCiphertext(c1_prime, ((ElGamalOnGroupElementCiphertext*) C_i_enc.get())->getC2());
		vec_C_enc2.push_back(make_shared<ElGamalOnGroupElementCiphertext>(C_i_enc2));
	}

	return vec_C_enc2;
}

pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> Server::fetch_key_pair(int u) {
	return table.get_key_pair(u);
}

vector<shared_ptr<AsymmetricCiphertext>> Server::potential_keys(vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc2, shared_ptr<AsymmetricCiphertext> K_enc2) {
	vector<shared_ptr<AsymmetricCiphertext>> B_enc2;

	for(shared_ptr<AsymmetricCiphertext> C_i_enc2 : vec_C_enc2) {
		shared_ptr<AsymmetricCiphertext> B_i_enc2 = elgamal->multiply(C_i_enc2.get(), K_enc2.get());
		B_enc2.push_back(B_i_enc2);
	}

	return B_enc2;
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
void Server::test_compare(biginteger t, biginteger max_S) {
	auto g = dlog->getGenerator();

	cout << "t: " << t << endl;
	cout << "max_S: " << max_S << endl << endl;

	for(int i=0; i<max_S; i++) {
		cout << "S: " << i << endl;

		biginteger S = i;

		auto g_S = dlog->exponentiate(g.get(), S);
		GroupElementPlaintext p_g_S(g_S);
		shared_ptr<AsymmetricCiphertext> c_g_S = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_g_S));

		vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc = compare(c_g_S, t, max_S);

		//test if there's a C_i that equals 1 when decrypted
		for(shared_ptr<AsymmetricCiphertext> C_i_enc : vec_C_enc) {
			shared_ptr<Plaintext> C_i = elgamal->decrypt(C_i_enc.get());
			cout << "C_i: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)C_i.get())->getElement()).get())->getElementValue() << endl;
		}

		cout << endl;
	}
}

//Permute order of comparison vector
void Server::test_permute(biginteger S, biginteger t, biginteger max_s) {
	auto g = dlog->getGenerator();

	auto g_S = dlog->exponentiate(g.get(), S);
	GroupElementPlaintext p_g_S(g_S);
	shared_ptr<AsymmetricCiphertext> c_g_S = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_g_S));

	vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc = compare(c_g_S, t, max_s);

	//print all C_i
	for(shared_ptr<AsymmetricCiphertext> C_i_enc : vec_C_enc) {
		shared_ptr<Plaintext> C_i = elgamal->decrypt(C_i_enc.get());
		cout << "C_i: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)C_i.get())->getElement()).get())->getElementValue() << endl;
	}

	cout << endl;

	vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc_prime = permute(vec_C_enc);

	//print all C_i when [[C]] has been permuted
	for(shared_ptr<AsymmetricCiphertext> C_i_enc_prime : vec_C_enc_prime) {
		shared_ptr<Plaintext> C_i_prime = elgamal->decrypt(C_i_enc_prime.get());
		cout << "C_i': " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)C_i_prime.get())->getElement()).get())->getElementValue() << endl;
	}
}

int main_sv() {
	Server sv(make_shared<OpenSSLDlogZpSafePrime>(128));

	sv.test_compare(4, 10);

	return 0;
}
