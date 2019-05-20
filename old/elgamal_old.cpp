#include <math.h>
#include <iostream>
#include <random>
#include <array>
#include <vector>
#include <chrono>
#include <time.h>
#include <gmp.h>

#include "elgamal.hpp"

//compile with g++ elgamal.cpp -lgmp

using namespace std;

Group::Group(mpz_t gg, mpz_t pp) {
	mpz_set(g, gg);
	mpz_set(p, pp);
}

Group::Group() {
	mpz_init(g);
	mpz_init(p);
	mpz_set_ui(g, 2);
	mpz_set_ui(p, 11);

	print_g();
	print_p();
}

Group::~Group() {
	mpz_clear(g);
	mpz_clear(p);
}

void Group::print_g() {
	//cout << "g: " << g << endl;
	gmp_printf("g: %Zd \n", g);
}

void Group::print_p() {
	//cout << "p: " << p << endl;
	gmp_printf("p: %Zd \n", p);
}


//find the multiplative inverse of element a in group G
//super simple and not very elegant solution, so please don't copy :)
/*int Group::inverse(int a) {
		int inv = 1;

		for(int i=1; i<p; i++) {
			int r = ((int) (i*a));
			if(r%p == 1) {
				inv = i;
				break;
			}
		}

		cout << "Inverse of " << a << ": " << inv << endl;

		return inv;
	}*/

//multiply two elements x,y \in G
/*mpz_t Group::mult(mpz_t x, mpz_t y) {
	mpz_t result;
	mpz_init(result);

	mpz_mul(result, x, y);

	return result;
}*/

ElGamal::ElGamal(Group GG): G(GG) {
	mpz_init(h);
}

ElGamal::ElGamal() {
	mpz_init(h);

	mpz_set_ui(G.g, 2);
	mpz_set_ui(G.p, 11);
}

ElGamal::~ElGamal() {
	mpz_clear(h);
}

void ElGamal::print_g() {
	gmp_printf("g: %Zd \n", G.g);
}

/*
void ElGamal::print_p() {
	cout << "p: " << G.p << endl;
}*/

/*void ElGamal::set_h(int a) {
	h = ((int) pow(G.g,a))%G.p;
		//cout << "h: " << h << endl;
}*/

//generate random key in G
void ElGamal::gen_key(mpz_t key) {
	unsigned long seed;
	gmp_randstate_t rstate;
	gmp_randinit_mt(rstate);
	gmp_randseed_ui(rstate, seed);

	mpz_urandomm(key, rstate, G.p);

	gmp_printf("a: %Zd \n", key);

	//Also set h
	//h = ((int) pow(G.g,a))%G.p;
	mpz_powm(h, G.g, key, G.p);

	gmp_printf("h: %Zd \n", h);
}
/*
//generate random plaintext in G
int ElGamal::gen_plaintext() {
	unsigned seed = chrono::system_clock::now().time_since_epoch().count();
	srand(seed);
	return rand()%(G.p-1)+1;
}*/

//encrypt message m
void ElGamal::encrypt(array<mpz_t, 2> c, mpz_t m, mpz_t r) {
	mpz_powm(c[0], G.g, r, G.p); //set c[0]
	mpz_powm(c[1], h, r, G.p); //set c[1], h^r
	mpz_mul(c[1], c[1], m); //set c[1], multiply m*h^r
	mpz_mod(c[1], c[1], G.p); //set c[1], m*h^r mod p

	//c[0] = ((int) pow(G.g,r))%G.p;
	//c[1] = G.mult(m, pow(h,r));
	//c[1] = ((int) (m*))%G.p;
}

/*
//decrypt ciphertext
int ElGamal::decrypt(array<int, 2> c, int a) {
	int powr = (int) pow(c[0], a);
	int m = (int) G.mult(c[1], G.inverse(pow(c[0], a)))%G.p;

	cout << "Decrypted ciphertext: " << m << endl;
	cout << endl;

	return m;
}

int ElGamal::get_h() {
	return h;
}

	//multiple two ciphertexts c1 and c2
array<int, 2> ElGamal::mult(array<int, 2> c1, array<int, 2> c2) {
	array<int, 2> result;

	result[0] = G.mult(c1[0], c2[0]);
	result[1] = G.mult(c1[1], c2[1]);

	return result;
}*/

int main() {
	mpz_t g;
	mpz_t p;
	mpz_init(g);
	mpz_init(p);
	mpz_set_ui(g, 2);
	mpz_set_ui(p, 11);

	//Group G;

	//ElGamal test(G);

	ElGamal test2;

	//test.print_g();

	mpz_t a;
	mpz_init(a);

	//test2.print_g();


	test2.gen_key(a);

/*
	cout << "key: " << a << endl;

	int plaintext = test.gen_plaintext();
	int r = 7;

	array<int, 2> ciphertext = test.encrypt(plaintext, r);
	int m = test.decrypt(ciphertext, a);
	int m2 = test.decrypt(ciphertext, 6);

	G.inverse(6);*/

	mpz_clear(g);
	mpz_clear(p);
	mpz_clear(a);

	return 0;
}
