#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <algorithm>
#include <stdlib.h>
#include <time.h>
#include <array>

//#include "server.hpp"

//#include <../libscapi/include/comm/Comm.hpp>
//#include <../libscapi/include/primitives/Prg.hpp>
//#include <../libscapi/include/primitives/Prf.hpp>

using namespace std;

//Create random T_u
vector<vector<int>> Server::create_T_u() {
	vector<vector<int>> T_u(k);
	for(int i=0; i<k; i++) {
			vector<int> lu_table_u(col);

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
int Server::create_key() {
		unsigned seed = chrono::system_clock::now().time_since_epoch().count();
		srand(seed);
		return rand()%100;
	}

	//add table entry with given T_u and key
void Server::add_table_entry(vector<vector<int>> T_u, int key)  {
		int u = 0;

		if(!table.empty()) {
			u = table.back().u+1;
		}

		TableEntry entry = {u, T_u, key};
		table.push_back(entry);
	}

	//add random table entry
void Server::add_table_entry() {
		//int u = table.back().u+1;
		int u = 0;

		if(!table.empty()) {
			u = table.back().u+1;
		}

		vector<vector<int>> T_u = create_T_u();
		int key = create_key();

		TableEntry entry = {u, T_u, key};

		table.push_back(entry);
	}

	//Build predefined table with 3 entries
void Server::build_table() {
		table.push_back({0, {{{1,2,3,4}, {5,6,7,8}, {9,1,2,3}}}, 0});
		table.push_back({1, {{{3,8,4,5}, {7,1,2,9}, {7,2,6,8}}}, 0});
		table.push_back({2, {{{6,8,3,2}, {8,2,7,8}, {9,1,4,0}}}, 0});
	}

	//Build table randomly given the number of entries
void Server::build_table(int entries) {
		for(int i=0; i<entries; i++) {
			add_table_entry();
		}
	}

//Print template T_u
void Server::print_T_u(vector<vector<int>> T_u) {
	cout << "{ ";

	for(vector<int> lu_table : T_u) {
		cout << "{";

		for(int i=0; i<lu_table.size(); i++) {
				cout << lu_table[i] << ",";
		}

		cout << "} ,";
	}

	cout << "}" << endl;
}

void Server::print_table() {
	for(TableEntry entry : table) {
		cout << "u: " << entry.u << "  " << "T_u: ";
		print_T_u(entry.T_u);
		cout << "key: " << entry.key << endl;
	}
}

//Fetch template T_u belonging to identity claim u from database
//Analogous to function fetch_table() from paper
vector<vector<int>> Server::fetch_template(int u) {
	vector<vector<int>> T_u = {{{0,0,0,0}, {0,0,0,0}, {0,0,0,0}}};

	for(TableEntry entry : table) {
		if(entry.u == u) {
			T_u = entry.T_u;
			break;
		}
	}

	return T_u;
}

	//Permute score set
vector<int> Server::permute(vector<int> C) {
		unsigned seed = chrono::system_clock::now().time_since_epoch().count();
		shuffle(C.begin(), C.end(), default_random_engine(seed));

		return C;
	}

	//Compare score set with parameter t
vector<int> Server::compare(int S, int t) {
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
void Server::D1(vector<int> C) {

	}


int main_sv() {
	Server sv;

	int S = 7;

	vector<int> C = sv.compare(S, sv.t);

	for(int c : C) {
		cout << c << endl;
	}

	cout << endl;

	for(int i=0; i<5; i++) {
		srand(chrono::system_clock::now().time_since_epoch().count());
		cout << rand()%10+1 << endl;
	}

	cout << endl;

	vector<vector<int>> T_u = sv.create_T_u();
	int key = 0;

	sv.build_table(5);

	sv.print_table();

	return 0;
}
