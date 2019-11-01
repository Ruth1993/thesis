#include "../include/math.hpp"

/*
*	Compute a mod b
*	Works if a is negative
*/
biginteger mod(biginteger a, biginteger b) {
	biginteger result = a % b;

	if (a < 0) {
		result = (a % b + b) % b;
	}

	return result;
}

/*
*	Convert an integer to byte array
*/
vector<unsigned char> int_to_byte(int a) {
	vector<unsigned char> result(4);

	for (int i = 0; i < 4; i++) {
		result[i] = (a >> (8 * (3 - i)));
	}

	return result;
}

/*
*	 Convert a byte array to integer
*/
int byte_to_int(vector<unsigned char> vec) {
	int result = 0;

	for (int i = 0; i < vec.size(); i++) {
		result = (result << 8) + vec[i];
	}

	return result;
}

/*
*	Randomly generate permutation matrix A_{ij}
*/
vector<vector<int>> permutation_matrix(int size) {
	vector<int> a(size, 0);
	vector<vector<int>> A(size, a);
	vector<int> r(size, 0);

	for (int i = 0; i < size; i++) {
		r[i] = i;
	}

	unsigned seed = chrono::system_clock::now().time_since_epoch().count();
	shuffle(r.begin(), r.end(), default_random_engine(seed));

	for (int i = 0; i < size; i++) {
		A[i][r[i]] = 1;
	}

	return A;
}

/*
*	Print permutation matrix A_{ij}
*/
void print_permutation_matrix(vector<vector<biginteger>> A) {
	int m = A[0].size();
	int n = A.size();

	cout << "A_{ij}: " << endl;
	for (int i = 0; i < m; i++) {
		for (int j = 0; j < n; j++) {
			cout << A[j][i] << " ";
		}

		cout << endl;
	}
	cout << endl;
}

int main_math() {
	vector<vector<int>> A = permutation_matrix(5);
}