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

	//int inverse(int a);

	//int mult(int x, int y);
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

	//void set_h(int a);

	void gen_key(mpz_t key);

	/*int gen_plaintext();

	//encrypt message m
	array<int, 2> encrypt(int m, int r);

	//decrypt ciphertext
	int decrypt(array<int, 2> c, int a);

	int get_h();

	//multiple two ciphertexts c1 and c2
	array<int, 2> mult(array<int, 2> c1, array<int, 2> c2);*/
};

int main();

#endif
