#include <iostream>
#include <vector>
#include <algorithm>
#include <stdlib.h>
#include <array>
#include <gmp.h>
#include <gmpxx.h>
#include <chrono>

#include "server.hpp"
#include "template.hpp"
#include "elgamal.hpp"

using namespace std;

//Create random T_u
void Server::create_temp(array<array<mpz_t, 4>, 3> &T) {
	for(int i=0; i<3; i++) {
    for(int j=0; j<4; j++) {
      mpz_init(T[i][j]);

			unsigned long seed = chrono::system_clock::now().time_since_epoch().count();
			gmp_randstate_t rstate;
			gmp_randinit_mt(rstate);
			gmp_randseed_ui(rstate, seed);

			mpz_urandomm(T[i][j], rstate, max_s.get_mpz_t());
			mpz_add(T[i][j], T[i][j], min_s.get_mpz_t());
    }
  }
}

//add random table entry
void Server::add_table_entry() {
	TableEntry entry;

	//%TODO change u to random
	mpz_init(entry.u);
	mpz_set_ui(entry.u, 1);

	array<array<mpz_t, 4>, 3> T;
	create_temp(T);
	mpz_set_T(entry.T_u, T);

	//%TODO change key to ElGamal key
	mpz_init(entry.key);
	mpz_set_ui(entry.key, 9);

	table.push_back(entry);
}

//add table entry with given T_u and key
void Server::add_table_entry(mpz_t u, array<array<mpz_t, 4>, 3>  T_u, mpz_t key)  {
		TableEntry entry;

		mpz_init(entry.u);
		mpz_set(entry.u, u);

		mpz_init_T(T_u);
		mpz_set_T(entry.T_u, T_u);

		mpz_init(entry.key);
		mpz_set(entry.key, key);

		table.push_back(entry);
}

void Server::mpz_init_T(array<array<mpz_t, 4>, 3>  &T) {
	for(int i=0; i<3; i++) {
		for(int j=0; j<4; j++) {
			mpz_init(T[i][j]);
		}
	}
}

void Server::mpz_set_T(array<array<mpz_t, 4>, 3>  &T1, array<array<mpz_t, 4>, 3>  T2) {
	for(int i=0; i<3; i++) {
		for(int j=0; j<4; j++) {
			mpz_set(T1[i][j], T2[i][i]);
		}
	}
}

int main() {
	Server sv;

	array<array<mpz_t, 4>, 3> templ;

	sv.create_temp(templ);

	//mpz_class u = 2;
	//mpz_class key = 8;

	//sv.add_table_entry(u.get_mpz_t(), templ, key.get_mpz_t());
	//sv.print_temp(templ);

	return 0;
}
