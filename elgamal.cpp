#include <math.h>
#include <iostream>
#include <random>
#include <array>
#include <vector>
#include <chrono>
#include <time.h>
#include <gmp.h>
#include <chrono>

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

//generate random key in G
void ElGamal::gen_key(mpz_t key) {
	unsigned long seed = chrono::system_clock::now().time_since_epoch().count();
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
void ElGamal::encrypt(Ciphertext &c, mpz_t m, mpz_t r) {
	mpz_powm(c.c0, G.g, r, G.p); //set c.c0

	mpz_powm(c.c1, h, r, G.p); //set c.c1, h^r
	mpz_mul(c.c1, c.c1, m); //set c.c1, multiply m*h^r
	mpz_mod(c.c1, c.c1, G.p); //set c.c1, m*h^r mod p

	gmp_printf("Encrypted message: (%Zd, %Zd) \n", c.c0, c.c1);
}


//decrypt ciphertext
void ElGamal::decrypt(mpz_t &m, Ciphertext c, mpz_t a) {
	//gmp_printf("c.c0: %Zd \n", c.c0);
	//gmp_printf("a: %Zd \n", a);
	mpz_powm(m, c.c0, a, G.p); //c.c0^a
	//gmp_printf("c.c0*a: %Zd \n", m);
	mpz_invert(m, m, G.p); //(c.c0^a)^-1
	//gmp_printf("(c.c0*a)^-1: %Zd \n", m);
	mpz_mul(m, m, c.c1); //c.c1 * (c.c0^a)^-1
	//gmp_printf("c.c1 * (c.c0*a)^-1: %Zd \n", m);
	mpz_mod(m, m, G.p); //c.c1 * (c.c0^a)^-1 mod p
	//gmp_printf("c.c1 * (c.c0*a)^-1 mod p: %Zd \n", m);

	gmp_printf("Decrypted ciphertext: %Zd \n", m);
}

int main() {
	mpz_t g;
	mpz_t p;
	mpz_init(g);
	mpz_init(p);
	mpz_set_ui(g, 2);
	mpz_set_ui(p, 11);

	ElGamal test2;

	//create key a
	mpz_t a;
	mpz_init(a);
	test2.gen_key(a);

	//generate random r for encryption
	mpz_t r;
	mpz_init(r);
	mpz_set_ui(r, 7);
	gmp_printf("r: %Zd \n", r);

	//encrypt message m
	mpz_t m1;
	mpz_init(m1);
	mpz_set_ui(m1, 4);

	Ciphertext c;
	mpz_init(c.c0);
	mpz_init(c.c1);

	test2.encrypt(c, m1, r);

	//decrypt ciphertext c
	mpz_t m2;
	mpz_init(m2);

	test2.decrypt(m2, c, a);

	mpz_clear(g);
	mpz_clear(p);
	mpz_clear(a);
	mpz_clear(c.c0);
	mpz_clear(c.c1);
	mpz_clear(m1);
	mpz_clear(m2);

	return 0;
}
