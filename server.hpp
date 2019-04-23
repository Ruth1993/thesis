#ifndef SERVER_H
#define SERVER_H

#include <vector>
#include <array>
#include "elgamal.h"
//#include <../libscapi/include/comm/Comm.hpp>
//#include <../libscapi/include/primitives/Prg.hpp>
//#include <../libscapi/include/primitives/Prf.hpp>

using namespace std;

class Server {
	public: 
	//Variables for templates
	const static int col; //size of tables in lookup table, which is 2^b in paper Joep Peeters
	const static int k; //number of features/lookup tables

	//Comparison variables

	int t; //threshold
	const int min_s; //left boundary of score domain
	const int max_s; //right boundary of score domain

	struct TableEntry {
		int u;
		array<array<int, col>, k> T_u;
		int key;
	};


	//Table
	vector<TableEntry> table;

	//Create random T_u
	array<array<int, col>, k> create_T_u();

	//Create random key
	//%TODO let key be in the range of [1,|G|]
	int create_key();

	void add_table_entry(array<array<int, col>, k> T_u, int key);

	void add_table_entry() {;

	//Build predefined table with 3 entries
	void build_table() {;

	//Build table randomly given the number of entries
	void build_table(int entries);

	//Print template T_u
	void print_T_u(array<array<int, col>, k> T_u);

	void print_table();

	//Fetch template T_u belonging to identity claim u from database
	array<array<int, col>, k> fetch_table(int u);

	//Set threshold t
	void set_t(int t_new);

	//Permute score set
	vector<int> permute(vector<int> C);

	//Compare score set with parameter t
	vector<int> compare(int S, int t);

	//Partial decryption function
	void D1(vector<int> C);
};

int main();
							
#endif
