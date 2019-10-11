/*
*	Created using libscapi (see https://crypto.biu.ac.il/SCAPI/)
*	Authors: Ruth Scholten
*/

#include "../include/schnorrsig.hpp"

using namespace std;

Signer::Signer() {
	ConfigFile cf("schnorr_params.txt");
	string q_string = cf.Value("", "q");
	string p_string = cf.Value("", "p");
	string g_string = cf.Value("", "g");

	dlog = make_shared<OpenSSLDlogZpSafePrime>(q_string, g_string, p_string);

	biginteger q = dlog->getOrder();
	auto g = dlog->getGenerator();

	H = make_shared<OpenSSLSHA256>();

	alpha = getRandomInRange(0, q-1, get_seeded_prg().get());
	y = dlog->exponentiate(g.get(), alpha);
	cout << "y in signer: " << ((OpenSSLZpSafePrimeElement*)y.get())->getElementValue() << endl;
}

/*
*	Sign message msg
*/
Signature Signer::sign(vector<byte> msg) {
	biginteger q = dlog->getOrder();
	auto g = dlog->getGenerator();

	biginteger k = getRandomInRange(0, q-1, get_seeded_prg().get());
	auto r = dlog->exponentiate(g.get(), k);

	cout << "r = g^k: " << ((OpenSSLZpSafePrimeElement*)r.get())->getElementValue() << endl;

	/*byte r_byte_arr[bytesCount(r)];
	encodeBigInteger(r, r_byte_arr, bytesCount(r));
	vector<byte> r_byte;
	copy_byte_array_to_byte_vector(r_byte_arr, bytesCount(r), r_byte, 0);

	print_byte_array(r_byte_arr, bytesCount(r), "r_byte_array: ");
	for (int i = 0; i < bytesCount(r); i++) {
		cout << r_byte[i] << ",";
	}*/
	
	//set c = H(m || r) \in Z_q
	H->update(msg, 0, msg.size());
	vector<byte> r_byte = dlog->decodeGroupElementToByteArray(r.get());
	H->update(r_byte, 0, r_byte.size());
	vector<byte> c_byte;
	H->hashFinal(c_byte, 0);

	byte c_byte_arr[c_byte.size()];
	copy_byte_vector_to_byte_array(c_byte, c_byte_arr, 0);

	biginteger c = mod(decodeBigInteger(c_byte_arr, c_byte.size()), q);

	cout << "c without mod: " << decodeBigInteger(c_byte_arr, c_byte.size()) << endl;
	cout << "c in signer: " << c << endl;
	cout << "-c in signer: " << mod(c * -1, q) << endl;
	auto y_pow_min_c = dlog->exponentiate(y.get(), mod(c * -1, q));
	cout << "y ^ -c in signer: " << ((OpenSSLZpSafePrimeElement*)y_pow_min_c.get())->getElementValue() << endl;
	cout << "alpha in signer: " << alpha << endl;

	//compute s = alpha*c + k \in Z_q
	biginteger s = mod(alpha * c + k, q);

	cout << "s in signer: " << s << endl;

	auto g_pow_s = dlog->exponentiate(g.get(), s);
	cout << "g^s in signer: " << ((OpenSSLZpSafePrimeElement*)g_pow_s.get())->getElementValue() << endl;

	auto v = dlog->multiplyGroupElements(g_pow_s.get(), y_pow_min_c.get());
	cout << "v in signer: " << ((OpenSSLZpSafePrimeElement*)v.get())->getElementValue() << endl;

	int size_c = bytesCount(c);
	byte c_mod_byte_arr[size_c];
	encodeBigInteger(c, c_mod_byte_arr, size_c);
	vector<byte> c_mod_byte;
	copy_byte_array_to_byte_vector(c_mod_byte_arr, size_c, c_mod_byte, 0);

	print_byte_array(c_mod_byte_arr, size_c, "c_mod_byte_array: ");
	for (int i = 0; i < size_c; i++) {
		cout << c_byte[i] << ",";
	}

	cout << endl << endl;

	Signature sig = { s, c };

	return sig;
}

Verifier::Verifier() {
	ConfigFile cf("schnorr_params.txt");
	string q_string = cf.Value("", "q");
	string p_string = cf.Value("", "p");
	string g_string = cf.Value("", "g");

	dlog = make_shared<OpenSSLDlogZpSafePrime>(q_string, g_string, p_string);

	H = make_shared<OpenSSLSHA256>();
}

bool Verifier::verify(vector<byte> msg, Signature sig, shared_ptr<GroupElement> y) {
	biginteger q = dlog->getOrder();

	biginteger s = sig.s;
	biginteger c = sig.c;
	
	cout << "c in verifier: " << c << endl;

	//compute v = g^s * y^-c \in Z_p
	auto g = dlog->getGenerator();
	auto y_pow_min_c = dlog->exponentiate(y.get(), mod(c * -1, q));
	cout << "-c in verifier: " << mod(c * -1, q) << endl;
	cout << "y ^ -c in verifier: " << ((OpenSSLZpSafePrimeElement*)y_pow_min_c.get())->getElementValue() << endl;
	auto g_pow_s = dlog->exponentiate(g.get(), s);
	cout << "g^s in verifier: " << ((OpenSSLZpSafePrimeElement*)g_pow_s.get())->getElementValue() << endl;
	//auto v = dlog->multiplyGroupElements(dlog->exponentiate(g.get(), s).get(), dlog->exponentiate(y.get(), c*-1).get());
	auto v = dlog->multiplyGroupElements(g_pow_s.get(), y_pow_min_c.get());
	cout << "v in verifier: " << ((OpenSSLZpSafePrimeElement*)v.get())->getElementValue() << endl;

	//compute hash = H(m || v)
	H->update(msg, 0, msg.size());
	vector<byte> v_byte = dlog->decodeGroupElementToByteArray(v.get());
	H->update(v_byte, 0, v_byte.size());
	vector<byte> hash;
	H->hashFinal(hash, 0);

	byte hash_arr[hash.size()];
	copy_byte_vector_to_byte_array(hash, hash_arr, 0);
	print_byte_array(hash_arr, hash.size(), "H(m || v): ");

	//Make sure H(m || v) \in Z_q
	biginteger hash_int = decodeBigInteger(hash_arr, hash.size());
	cout << "hash_int: " << hash_int << endl;
	biginteger hash_int_mod = mod(hash_int, q);
	int size_hash = bytesCount(hash_int_mod);
	byte hash_arr_mod[size_hash];
	encodeBigInteger(hash_int_mod, hash_arr_mod, size_hash);
	vector<byte> hash_mod;
	copy_byte_array_to_byte_vector(hash_arr_mod, size_hash, hash_mod, 0);

	return (c == hash_int_mod);
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