#include <iostream>
#include <array>
#include <chrono>
#include <random>
#include <stdlib.h>
#include <time.h>
#include <vector>

#include "sensor.hpp"
#include "../libscapi/include/mid_layer/OpenSSLSymmetricEnc.hpp"
#include "../libscapi/include/primitives/DlogOpenSSL.hpp"
#include "../libscapi/include/mid_layer/ElGamalEnc.hpp"
#include "../libscapi/include/infra/Common.hpp"

using namespace std;

/*Sensor::Sensor(auto dlogg) {
	dlog = dlogg;
}*/

//Convert an integer to byte array of size len
vector<unsigned char> Sensor::int_to_byte(int a, int len) {
	vector<unsigned char> result;

	for(int i=0; i<len; i++) {
		result.push_back(a >> (8*(len-1-i)));
	}

	return result;
}

//Convert an integer to byte array of size 4 (standard)
vector<unsigned char> Sensor::int_to_byte(int a) {
  int_to_byte(a, 4);
}

//Convert a byte array to integer
int Sensor::byte_to_int(vector<unsigned char> vec) {
  int result = 0;

  for(int i=0; i<vec.size(); i++) {
    result = (result << 8) + vec[i];
  }

  return result;
}

//Pad input with zeros (least significant bits) to match number of bytes
void Sensor::pad(vector<unsigned char> &input, int bytes) {
	int i = bytes-input.size()*8;
	if(i > 0) {
		for(int j = 0; j<i; j+=8) {
			vector<unsigned char> byte_zeros = int_to_byte(0, 1);
			input.push_back(byte_zeros[0]);
		}
	}
}

void Sensor::enroll() {
	auto dlog = make_shared<OpenSSLDlogZpSafePrime>(128);
	OpenSSLCTREncRandomIV aes_enc("AES");

	//Step 4: pick k \in_R [0, |G|]
	auto g = dlog->getGenerator();
	biginteger p = dlog->getOrder();

	auto gen = get_seeded_prg();
	biginteger k = getRandomInRange(0, p-1, gen.get()); //generate random k

	//K = g^k
	auto cap_k = dlog->exponentiate(g.get(), k);


	//Step 5: encrypt K

	//Step 6: AES_K(1)
	//First copy cap_k to byte vector in order to use in AES encryption
	vector<unsigned char> vec_cap_k = dlog->decodeGroupElementToByteArray(cap_k.get());
	cout << vec_cap_k.size() << endl;

	int a = 0;
	vector<unsigned char> v_a = int_to_byte(a, 1);
	int a2 = byte_to_int(v_a);

	cout << a2 << endl;

	pad(vec_cap_k, 128);

	cout << vec_cap_k.size() << endl;

	//byte arr_cap_k[15];
	//copy_byte_vector_to_byte_array(vec_cap_k, &arr_cap_k, 0);
	//print_byte_array(arr_cap_k, vec_cap_k.size(), "");
	SecretKey aes_cap_k = SecretKey(vec_cap_k, "");
	aes_enc.setKey(aes_cap_k);

	vector<unsigned char> vec = int_to_byte(1);
	ByteArrayPlaintext p1(vec);
	shared_ptr<SymmetricCiphertext> cipher = aes_enc.encrypt(&p1);

	shared_ptr<Plaintext> p2 = aes_enc.decrypt(cipher.get());
	//test

	cout << "Plaintext before encryption: " << byte_to_int(p1.getText()) << endl;
	cout << "Ciphertext: " << ((ByteArraySymCiphertext *)cipher.get())->toString() << endl;
	cout << "Plaintext after decryption: " << byte_to_int(((ByteArrayPlaintext *)p2.get())->getText()) << endl;

}

int main() {
	Sensor ss;
	ss.enroll();

	return 0;
}

//Capture vec_p from biometrics
//Return random u and vec_p
//Note that what captured in this function is not actually vec_p itself, but for simplicity purposes the column number which is later selected in the look_up function.
/*pair<int, vector<int>> Sensor::capture() {
	int u = 0;
	vector<int> vec_p(k);

	for(int i=0; i<k; i++) {
		unsigned seed = chrono::system_clock::now().time_since_epoch().count();
		srand(seed);
		vec_p[i] = rand()%col;
	}

	unsigned seed = chrono::system_clock::now().time_since_epoch().count();
	srand(seed);
	u = rand();

	return make_pair(u, vec_p);
}*/

//Capture function with given identity claim u
/*pair<int, vector<int>> Sensor::capture(int u) {
	vector<int> vec_p(k);

	for(int i=0; i<k; i++) {
		unsigned seed = chrono::system_clock::now().time_since_epoch().count();
		srand(seed);
		vec_p[i] = rand()%col;
	}

	unsigned seed = chrono::system_clock::now().time_since_epoch().count();
	srand(seed);
	u = rand();

	return make_pair(u, vec_p);
}*/

	//Lookup similarity scores in T_u by selecting columns for each p in vec_p
	//%TODO initialise vec_s, because size is known
	/*vector<int> Sensor::look_up(vector<vector<int>> T_u, vector<int> vec_p) {
		vector<int> vec_s;

		for(int i=0; i<T_u.size(); i++) {
			vector<int> table = T_u[i];
			int p = vec_p[i];
			int s = table[p];

			cout << "s: " << s << endl;

			vec_s.push_back(s);
		}

		return vec_s;
	}*/

//Add up all s_i \in S
/*int Sensor::calc_score(vector<int> vec_s) {
	int S = 0;

	for(int s : vec_s) {
		S += s;
	}

	cout << "S: " << S << endl;

	return S;
}*/


//Decryption function D2
/*void Sensor::D2() {

}*/

	//Check if there is a match by looking if there is a c for which c==0
	/*bool Sensor::has_match(vector<int> C) {
		bool result = false;

		for(int c : C) {
			if(c == 0) {
				//There is a match
				result = true;
			}
		}

		return result;
	}*/

/*int main_ss() {
	Sensor ss;

	vector<vector<int>> T_u = {{{1,2,3,4}, {5,6,7,8}, {9,10,11,12}}};
	pair<int, vector<int>> cap = ss.capture();

	vector<int> vec_p = cap.second;

	for(int p : vec_p) {
		cout << "p: " << p << endl;
	}

	vector<int> vec_s = ss.look_up(T_u, vec_p);

	int S = ss.calc_score(vec_s);

	return 0;
}*/
