#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <algorithm>
#include <stdlib.h>
#include <time.h>
//#include <../libscapi/include/comm/Comm.hpp>
//#include <../libscapi/include/primitives/Prg.hpp>
//#include <../libscapi/include/primitives/Prf.hpp>

using namespace std;

int t = 8;
const int max_s = 10;

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

	return 0;
}
