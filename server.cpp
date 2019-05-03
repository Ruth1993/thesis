#include <iostream>
#include <vector>
#include <algorithm>
#include <stdlib.h>
#include <array>
#include <gmp.h>
#include <gmpxx.h>
#include <chrono>

#include "server.hpp"

using namespace std;

//add random table entry
void Server::add_table_entry() {
	TableEntry entry;

	//%TODO change u to random
	mpz_init(entry.u);
	mpz_set_ui(entry.u, 1);

	Template T(min_s, max_s);
	entry.T_u = T;

	//%TODO change key to ElGamal key
	mpz_init(entry.key);
	mpz_set_ui(entry.key, 9);

	table.push_back(entry);
}

void Server::print_table() {
	for(TableEntry entry : table) {
		gmp_printf("u: %Zd, T_u: ", entry.u);
		entry.T_u.print();
		gmp_printf("key: %Zd", entry.key);
	}
}

/*
//add table entry with given T_u and key
void Server::add_table_entry(mpz_t u, Template  T_u, mpz_t key)  {
		TableEntry entry;

		mpz_init(entry.u);
		mpz_set(entry.u, u);

		mpz_init_T(T_u);
		mpz_set_T(entry.T_u, T_u);

		mpz_init(entry.key);
		mpz_set(entry.key, key);

		table.push_back(entry);
}*/

/*
void Server::mpz_init_T(Template  &T) {
	for(int i=0; i<3; i++) {
		for(int j=0; j<4; j++) {
			mpz_init(T[i][j]);
		}
	}
}

void Server::mpz_set_T(Template  &T1, Template T2) {
	for(int i=0; i<3; i++) {
		for(int j=0; j<4; j++) {
			mpz_set(T1[i][j], T2[i][i]);
		}
	}
}*/

int main() {
	Server sv;

	sv.add_table_entry();
	sv.print_table();

	return 0;
}
