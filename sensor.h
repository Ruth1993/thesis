#include <iostream>
#include <array>
#include <chrono>
#include <random>
#include <stdlib.h>
#include <time.h>
#include <vector>

#include "sensor.hpp"
//#include "elgamal.h"

using namespace std;
	
	//Capture vec_p from biometrics
	//Note that what captured in this function is not actually vec_p itself, but for simplicity purposes the column number which is later selected in the look_up function.
	vector<int> Sensor::capture() {
		vector<int> vec_p(k);

		for(int i=0; i<k; i++) {
			unsigned seed = chrono::system_clock::now().time_since_epoch().count();
			srand(seed);
			vec_p[i] = rand()%col;
		}

		return vec_p;
	}

	//Lookup similarity scores in T_u by selecting columns for each p in vec_p
	//%TODO initialise vec_s, because size is known
	vector<int> Sensor::look_up(vector<vector<int>> T_u, vector<int> vec_p) {
		vector<int> vec_s;

		for(int i=0; i<T_u.size(); i++) {
			vector<int> table = T_u[i];
			int p = vec_p[i];
			int s = table[p];

			cout << "s: " << s << endl;

			vec_s.push_back(s);
		}

		return vec_s;
	}

	int Sensor::calc_score(vector<int> vec_s) {
		int S = 0;

		for(int s : vec_s) {
			S += s;
		}

		cout << "S: " << S << endl;

		return S;
	}

	void Sensor::D2() {

	}

	//Check if there is a match by looking if there is a c for which c==0
	bool Sensor::has_match(vector<int> C) {
		bool result = false;

		for(int c : C) {
			if(c == 0) {
				//There is a match
				result = true;
			}
		}

		return result;
	}

int main() {
	Sensor ss;
	
	vector<vector<int>> T_u = {{{1,2,3,4}, {5,6,7,8}, {9,10,11,12}}};
	vector<int> vec_p = ss.capture();

	for(int p : vec_p) {
		cout << "p: " << p << endl;
	}

	vector<int> vec_s = ss.look_up(T_u, vec_p);

	int S = ss.calc_score(vec_s);
	
	return 0;
}