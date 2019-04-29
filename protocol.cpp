#include <iostream>

#include "sensor.hpp"
#include "server.hpp"

using namespace std;

int main() {
	Sensor ss;
	Server sv;

	int t = 8;

	//Enrollment procedure
	pair<int, vector<int>> cap1 = ss.capture();

	//Verification procedure

	//Step 1
	pair<int, vector<int>> cap2 = ss.capture();
	int u = cap2.first;
	vector<int> vec_p = cap2.second;

	//Step 3
	vector<vector<int>> T_u = sv.fetch_template(u);

	//Step 5
	vector<int> vec_s = ss.look_up(T_u, vec_p);

	//Step 6
	int S = ss.calc_score(vec_s);

	//Step 8 Compare S with threshold t
	vector<int> C = sv.compare(S, t);

	//Step 9 Permute
	vector<int> C_x = sv.permute(C);

	//Step 10 Deecrypt

	//Step 11 Fetch key

	return 0;
}
