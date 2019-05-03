#ifndef SERVER_H
#define SERVER_H

#include <vector>
#include <array>
#include <gmp.h>
#include <gmpxx.h>

#include "template.hpp"
#include "elgamal.hpp"

using namespace std;

class Server {
	private:
	struct TableEntry {
		mpz_t u;
		Template  T_u;
		mpz_t key;
	};

	//Table
	vector<TableEntry> table;

	public:
	//Comparison variables

	mpz_class t = 8; //threshold
	mpz_class min_s = 0; //left boundary of score domain
	mpz_class max_s = 10; //right boundary of score domain

/*
	//Create random key
	//%TODO let key be in the range of [1,|G|]
	int create_key();
*/
	//void add_table_entry(mpz_t u, Template  T_u, mpz_t key);

	void add_table_entry();

	//void mpz_init_T(Template  &T);

	//void mpz_set_T(Template  &T1, Template  T2);

	//Build predefined table with 3 entries
	//void build_table();

	//Build table randomly given the number of entries
	//void build_table(int entries);

	//Print template T_u
	//void print_temp(array<array<mpz_t, 4>, 3> T);


	void print_table();
/*
	//Fetch template T_u belonging to identity claim u from database
	vector<vector<int>> fetch_template(int u);

	//Set threshold t
	void set_t(int t_new);

	//Permute score set
	vector<int> permute(vector<int> C);

	//Compare score set with parameter t
	vector<int> compare(int S, int t);

	//Partial decryption function
	void D1(vector<int> C);*/
};

int main();

#endif
