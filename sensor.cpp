#include <iostream>

using namespace std;

int calc_score(int[] sim_scores) {
	int result = 0;

	for(int i=0; i<sim_scores.size(); i++) {
		result += sim_scores[i];
	}

	return result;
}

vec<int> look_up(int* t_u, int* vec_p) {
	vec<int> vec_s;

	return vec_s;
}

int main() {
	int t_u[3][3] = { {2,1,8}, {5,4,3}, {7,6,9} };
	return 0;
}
