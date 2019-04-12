#include <iostream>

using namespace std;

int calc_score(int[] sim_scores) {
	int result = 0;

	for(int i=0; i<sim_scores.size(); i++) {
		result += sim_scores[i];
	}

	return result;
}

int main() {
	return 0;
}
