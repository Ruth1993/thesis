#include <math.h>
#include <iostream>
#include <random>
#include <vector>

using namespace std;

class Group {
	public: 
	int g;
	int p;

	void print_g() {
		cout << "g: " << g << endl;
	}

	void print_p() {
		cout << "p: " << p << endl;
	}

	
	//find the multiplative inverse of a in group G
	//super simple and not very elegant solution, so please don't copy :)
	int mult_inverse(int a) {
	int inverse = 1;

	for(int i=1; i<p; i++) {
		if(((int) (i*a))%p == 1) {
			break;
		}
	}
	
	cout << "Inverse of " << a << ": " << inverse << endl;

	return inverse;	
	}
};

class ElGamal {
	public:
	Group G;
	
	private:
	int h; //public key

	public:
	void print_g() {
		cout << "g: " << G.g << endl;
	}

	void print_p() {
		cout << "p: " << G.p << endl;
	}

	void set_h(int a) {
		h = ((int) pow(G.g,a))%G.p;
	}

	//encrypt message m
	vector<int> encrypt(int m, int r) {
		vector<int> c(2);

		c[0] = ((int) pow(G.g,r))%G.p;
		c[1] = ((int) (m*pow(h,r)))%G.p;

		cout << "Ciphertext: (" << c[0] << ", " << c[1] << ")" << endl;

		return c;
	}

	//decrypt ciphertext
	int decrypt(vector<int> c, int a) {
		//int inv_a = 
		int m = c[1]/(pow(c[0],a));

		cout << "Decrypted ciphertext: " << m << endl;

		return m;
	}

	int get_h() {
		return h;
	}
};

int main() {
	int g = 2;
	int p = 11;

	Group G;
	G.g = 2;
	G.p = 11;
	
	ElGamal test;
	test.G = G;
	
	G.print_g();
	G.print_p();

	test.print_g();
	test.print_p();

	int a = 9;

	test.set_h(a);

	int plaintext = 4;
	int r = 7;

	vector<int> ciphertext = test.encrypt(plaintext, r);
	int m1 = test.decrypt(ciphertext, a);
	int m2 = test.decrypt(ciphertext, 6);

	
	G.mult_inverse(a);

	return 0;
}
