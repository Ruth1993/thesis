#include <iostream>
#include <array>
#include <chrono>
#include <random>
#include <stdlib.h>
#include <time.h>
#include <vector>

using namespace std;

class Sensor {
	private:
	//%TODO make sure variables below are consistent for sensor and server
	static int col;
	static int k;
	
	public:
	Sensor() {
		col = 4;
		k = 3;
	}
	
	//Capture vec_p from biometrics
	//Note that what captured in this function is not actually vec_p itself, but for simplicity purposes the column number which is later selected in the look_up function.
	array<int, k> capture() {
		array<int, k> vec_p;

		for(int i=0; i<k; i++) {
			unsigned seed = chrono::system_clock::now().time_since_epoch().count();
			srand(seed);
			vec_p[i] = rand()%col;
		}

		return vec_p;
	}

	//Lookup similarity scores in T_u by selecting columns for each p in vec_p
	vector<int> look_up(array<array<int, col>, k> T_u, array<int, k> vec_p) {
		vector<int> vec_s;

		for(int i=0; i<T_u.size(); i++) {
			array<int, col> table = T_u[i];
			int p = vec_p[i];
			int s = table[p];

			cout << "s: " << s << endl;

			vec_s.push_back(s);
		}

		return vec_s;
	}

	int calc_score(vector<int> vec_s) {
		int S = 0;

		for(int s : vec_s) {
			S += s;
		}

		cout << "S: " << S << endl;

		return S;
	}

	void D2() {

	}

	//Check if there is a match by looking if there is a c for which c==0
	bool has_match(vector<int> C) {
		bool result = false;

		for(int c : C) {
			if(c == 0) {
				//There is a match
				result = true;
			}
		}

		return result;
	}
};

int main() {
	Sensor s1;
	
	array<array<int, col>, k> T_u = {{{1,2,3,4}, {5,6,7,8}, {9,10,11,12}}};
	array<int, k> vec_p = s1.capture();

	for(int p : vec_p) {
		cout << "p: " << p << endl;
	}

	vector<int> vec_s = s1.look_up(T_u, vec_p);

	int S = s1.calc_score(vec_s);
	
	return 0;
}
