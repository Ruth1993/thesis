/*
*	Created using libscapi (see https://crypto.biu.ac.il/SCAPI/)
*	Authors: Ruth Scholten
*/

#include "../include/schnorrsig.hpp"

using namespace std;

Signer::Signer() {
	ConfigFile cf("dlog_params.txt");
	string q_string = cf.Value("", "q");
	string p_string = cf.Value("", "p");
	string g_string = cf.Value("", "g");

	//dlog = make_shared<OpenSSLDlogZpSafePrime>(q_string, g_string, p_string);
	dlog = make_shared<OpenSSLDlogECF2m>("../../libscapi/include/configFiles/NISTEC.txt", "K-233");
	//dlog = make_shared<OpenSSLDlogECFp>("B-163");

	biginteger q = dlog->getOrder();
	auto g = dlog->getGenerator();

	H = make_shared<OpenSSLSHA512>();

	alpha = getRandomInRange(0, q-1, get_seeded_prg().get());
	y = dlog->exponentiate(g.get(), alpha);
}

/*
*	Sign message msg
*/
Signature Signer::sign(vector<byte> msg) {
	biginteger q = dlog->getOrder();
	auto g = dlog->getGenerator();

	//compute r = g^k \in Z*_p
	biginteger k = getRandomInRange(0, q-1, get_seeded_prg().get());
	auto r = dlog->exponentiate(g.get(), k);
	
	auto start_hash = std::chrono::high_resolution_clock::now();
	//set c = H(m || r) \in Z_q
	H->update(msg, 0, msg.size());
	vector<byte> r_byte = dlog->decodeGroupElementToByteArray(r.get());
	H->update(r_byte, 0, r_byte.size());
	vector<byte> c_byte;
	H->hashFinal(c_byte, 0);
	auto end_hash = std::chrono::high_resolution_clock::now();

	cout << "time hash: " << chrono::duration_cast<chrono::microseconds>(end_hash - start_hash).count() << endl;
	byte c_byte_arr[c_byte.size()];
	copy_byte_vector_to_byte_array(c_byte, c_byte_arr, 0);
	biginteger c = mod(decodeBigInteger(c_byte_arr, c_byte.size()), q);

	//compute s = alpha*c + k \in Z_q
	biginteger s = mod(alpha * c + k, q);

	Signature sig = { s, c };

	return sig;
}

Verifier::Verifier() {
	ConfigFile cf("dlog_params.txt");
	string q_string = cf.Value("", "q");
	string p_string = cf.Value("", "p");
	string g_string = cf.Value("", "g");

	//dlog = make_shared<OpenSSLDlogZpSafePrime>(q_string, g_string, p_string);
	dlog = make_shared<OpenSSLDlogECF2m>("../../libscapi/include/configFiles/NISTEC.txt", "K-233");

	H = make_shared<OpenSSLSHA512>();
}

bool Verifier::verify(vector<byte> msg, Signature sig, shared_ptr<GroupElement> y) {
	biginteger q = dlog->getOrder();

	biginteger s = sig.s;
	biginteger c = sig.c;

	//compute v = g^s * y^-c \in Z_p
	auto g = dlog->getGenerator();
	auto y_pow_min_c = dlog->exponentiate(y.get(), mod(c * -1, q));
	auto g_pow_s = dlog->exponentiate(g.get(), s);
	//auto v = dlog->multiplyGroupElements(dlog->exponentiate(g.get(), s).get(), dlog->exponentiate(y.get(), c*-1).get());
	auto v = dlog->multiplyGroupElements(g_pow_s.get(), y_pow_min_c.get());

	//compute hash = H(m || v)
	H->update(msg, 0, msg.size());
	vector<byte> v_byte = dlog->decodeGroupElementToByteArray(v.get());
	H->update(v_byte, 0, v_byte.size());
	vector<byte> hash;
	H->hashFinal(hash, 0);

	//Make sure H(m || v) \in Z_q
	byte hash_arr[hash.size()];
	copy_byte_vector_to_byte_array(hash, hash_arr, 0);
	biginteger hash_int = mod(decodeBigInteger(hash_arr, hash.size()), q);

	return (c == hash_int);
}

/*
*	Key generation function which is executed offline once
*	Save keys manually in schnorr_params.txt
*/
void key_gen(int lambda) {
	//int lambda = 256;
	biginteger q;
	biginteger p;
	biginteger g;

	bool found = false;
	int r = 2;
	while (!found) {
		q = getRandomPrime(lambda, 90, get_seeded_prg().get());
		p = q * r + 1;

		if (isPrime(p)) {
			found = true;
			cout << "q: " << q << endl;
			cout << "p: " << p << endl;
			cout << "#bits: " << NumberOfBits(p) << endl;
		}
	}

	for (biginteger h = 2; h < p; h++) {
		g = pow(h, r) % p;
		if (g != 1) {
			cout << "h: " << h << endl;
			cout << "g: " << g << endl;
			break;
		}
	}
}


int main_schnorr(int argc, char* argv[]) {
	shared_ptr<Signer> signer = make_shared<Signer>();
	shared_ptr<Verifier> verifier = make_shared<Verifier>();

	auto y = signer->y;

	vector<byte> msg;
	gen_random_bytes_vector(msg, 4, get_seeded_prg().get());

	Signature sig = signer->sign(msg);

	cout << "signature verified: " << verifier->verify(msg, sig, y) << endl;
	
	return 0;
}