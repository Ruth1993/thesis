#ifndef SENSOR_H
#define SENSOR_H

#include <vector>

using namespace std;

class Sensor {
	public:
		//ElGamal and AES objects

	//Sensor();

	vector<unsigned char> int_to_byte(int a);

	vector<unsigned char> int_to_byte(int a, int len);

	int byte_to_int(vector<unsigned char> vec);

	void pad(vector<unsigned char> &input, int bytes) ;

	void enroll();

	//Capture vec_p from biometrics
	//Note that what captured in this function is not actually vec_p itself, but for simplicity purposes the column number which is later selected in the look_up function.
	//pair<int, vector<int>> capture();

	//pair<int, vector<int>> capture(int u);

	//Lookup similarity scores in T_u by selecting columns for each p in vec_p
	//%TODO initialise vec_s, because size is known
	//vector<int> look_up(vector<vector<int>> T_u, vector<int> vec_p);

	//int calc_score(vector<int> vec_s);

	//void D2();

	//Check if there is a match by looking if there is a c for which c==0
	//bool has_match(vector<int> C);
};

int main();

#endif
