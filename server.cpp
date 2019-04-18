
#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <algorithm>
#include <stdlib.h>
#include <time.h>
#include <array>
//#include <../libscapi/include/comm/Comm.hpp>
//#include <../libscapi/include/primitives/Prg.hpp>
//#include <../libscapi/include/primitives/Prf.hpp>

using namespace std;

//Variables for templates
const int col = 4; //size of tables in lookup table, which is 2^b in paper Joep Peeters
const int k = 3; //number of features/lookup tables

//Comparison variables

int t = 8; //threshold
const int min_s = 0; //boundary of score domain
const int max_s = 10; //boundary of score domain

struct TableEntry {
	int u;
	array<array<int, col>, k> T_u;
	int key;
};


//Table
vector<TableEntry> table;

//Create random T_u
array<array<int, col>, k> create_T_u() {
	array<array<int, col>, k> T_u;

	for(int i=0; i<k; i++) {
		array<int, col> lu_table_u;
		
		//cout << "{";

		for(int j=0; j<col; j++) {
			unsigned seed = chrono::system_clock::now().time_since_epoch().count();
			srand(seed);
			lu_table_u[j] = rand()%max_s+min_s;
			
			//cout << lu_table_u[j] << ", ";
		}
		
		//cout << "}" << endl;

		T_u[i] = lu_table_u;
		
	}
	
	
	return T_u;
}

//Create random key
//%TODO let key be in the range of [1,|G|]
int create_key() {
	unsigned seed = chrono::system_clock::now().time_since_epoch().count();
	srand(seed);
	return rand()%100;
}

//Build predefined table with 3 entries
void build_table() {
	table.push_back({0, {{{1,2,3,4}, {5,6,7,8}, {9,1,2,3}}}, 0});
	table.push_back({1, {{{3,8,4,5}, {7,1,2,9}, {7,2,6,8}}}, 0});
	table.push_back({2, {{{6,8,3,2}, {8,2,7,8}, {9,1,4,0}}}, 0});
}

//Build table randomly given the number of entries
void build_table(int entries) {
	for(int i=0; i<entries; i++) {
		//First create T_u
		
	}
}

void add_table_entry(int u, array<array<int, col>, k> T_u, int key) {
	TableEntry entry = {u, T_u, key};
}

void add_table_entry() {
	array<array<int, col>, k> T_u = create_T_u();
	int key = create_key();
	
	
}

//Fetch template T_u belonging to identity claim u from database
array<array<int, col>, k> fetch_table(int u) {
	array<array<int, col>, k> T_u = {{{1,2,3,4}, {5,6,7,8}, {9,10,11,12}}};

	return T_u;
}

//Set threshold t
void set_t(int t_new) {
	t = t_new;
}

//Permute score set
vector<int> permute(vector<int> C) {
	unsigned seed = chrono::system_clock::now().time_since_epoch().count();
	shuffle(C.begin(), C.end(), default_random_engine(seed));
	
	return C;
}

//Compare score set with parameter t
vector<int> compare(int S, int t) {
	vector<int> C(max_s-t+1);

	for(int i=0; i<=max_s-t; i++) {
		//Multiplicatively blind the elements with random r and add to C
		//TODO r should be in the range (1, |G|), so change number 10 to |G|
		unsigned seed = chrono::system_clock::now().time_since_epoch().count();
		srand(seed);
		int r = rand()%10+1;
		C[i] = (r*(S-t-i));
	}

	return C;
}

//Partial decryption function
void D1(vector<int> C) {

}

void randomkey() {


}



int main() {
	int S = 7;

	vector<int> C = compare(S, t);

	for(int c : C) {
		cout << c << endl;
	}

	cout << endl;

	for(int i=0; i<5; i++) {
		srand(chrono::system_clock::now().time_since_epoch().count());
		cout << rand()%10+1 << endl;
	}

	cout << endl;
	
	array<array<int, col>, k> T_u = create_T_u();

	return 0;
}
