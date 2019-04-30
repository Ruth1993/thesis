#ifndef ELGAMAL_H
#define ELGAMAL_H

#include <array>
#include <gmp.h>
//#include <flint.h>
//#include <fmpz.h>

using namespace std;

class Group {
	public:
	mpz_t g, p;

	Group(mpz_t gg, mpz_t pp);

	Group();

	~Group();

	void print_g();

	void print_p();
};

class ElGamal {
	private:
	mpz_t h; //public key

	public:
	Group G;

	ElGamal(Group GG);

	ElGamal();

	~ElGamal();

	void print_g();

	void gen_key(mpz_t key);

	/*int gen_plaintext();*/

	//encrypt message m
	void encrypt(array<mpz_t, 2> &c, mpz_t m, mpz_t r);

	//decrypt ciphertext
	void decrypt(mpz_t &m, array<mpz_t, 2> c, mpz_t a);
};

int main();

#endif
