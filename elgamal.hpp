#ifndef ELGAMAL_H
#define ELGAMAL_H

#include<array>

using namespace std;

class Group {
	public: 
	int g;
	int p;

	void print_g();

	void print_p();

	int inverse(int a);
	
	int mult(int x, int y);	
};

class ElGamal {
	private:
	int h; //public key

	public:
	Group G;
	
	struct CipherText {
		int c_0;
		int c_1;
	}
	
	void print_g();

	void print_p();

	void set_h(int a);

	//encrypt message m
	array<int, 2> encrypt(int m, int r);

	//decrypt ciphertext
	int decrypt(array<int, 2> c, int a);

	int get_h();
	
	//multiple two ciphertexts c1 and c2
	array<int, 2> mult(array<int, 2> c1, array<int, 2> c2);
};

int main() {;

#endif