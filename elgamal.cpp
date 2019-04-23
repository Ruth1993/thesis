#include <math.h>
#include <iostream>
#include <random>
#include <array>

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

	
	//find the multiplative inverse of element a in group G
	//super simple and not very elegant solution, so please don't copy :)
	int inverse(int a) {
		int inv = 1;

		for(int i=1; i<p; i++) {
			int r = ((int) (i*a));
			if(r%p == 1) {
				inv = i;
				break;
			}
		}

		cout << "Inverse of " << a << ": " << inv << endl;

		return inv;	
	}
	
	//multiply two elements x,y \in G
	int mult(int x, int y) {
		return (int) (x*y)%p;
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
		//cout << "h: " << h << endl;
	}

	//encrypt message m
	array<int, 2> encrypt(int m, int r) {
		array<int, 2> c;

		c[0] = ((int) pow(G.g,r))%G.p;
		c[1] = G.mult(m, pow(h,r));
		//c[1] = ((int) (m*))%G.p;

		cout << "Original plaintext: " << m << endl;
		cout << "Ciphertext: (" << c[0] << ", " << c[1] << ")" << endl;
		cout << endl;

		return c;
	}

	//decrypt ciphertext
	int decrypt(array<int, 2> c, int a) {
		int powr = (int) pow(c[0], a);
		int m = (int) G.mult(c[1], G.inverse(pow(c[0], a)))%G.p;
		
		cout << "Decrypted ciphertext: " << m << endl;
		cout << endl;

		return m;
	}

	int get_h() {
		return h;
	}
	
	//multiple two ciphertexts c1 and c2
	array<int, 2> mult(array<int, 2> c1, array<int, 2> c2) {
		array<int, 2> result;
		
		result[0] = G.mult(c1[0], c2[0]);
		result[1] = G.mult(c1[1], c2[1]);
		
		return result;
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

	int a = 9;

	test.set_h(a);

	int plaintext = 4;
	int r = 7;

	array<int, 2> ciphertext = test.encrypt(plaintext, r);
	int m = test.decrypt(ciphertext, a);
	int m2 = test.decrypt(ciphertext, 6);
	
	G.inverse(6);

	return 0;
}
