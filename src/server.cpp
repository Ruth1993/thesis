#include <iostream>
#include <vector>
#include <algorithm>
#include <stdlib.h>
#include <array>
#include <chrono>

#include "../include/server.hpp"

using namespace std;

Server::Server(string config_file_path) {
	//Intialize encryption objects
	aes_enc = make_shared<OpenSSLCTREncRandomIV>("AES");

	ConfigFile cf(config_file_path);
	string p = cf.Value("", "p");
	string g = cf.Value("", "g");
	string q = cf.Value("", "q");
	dlog = make_shared<OpenSSLDlogZpSafePrime>(q, g, p);
	elgamal = make_shared<ElGamalOnGroupElementEnc>(dlog);

	//Generate and set ElGamal keypair
	auto pair = elgamal->generateKey();

	pk_own = pair.first;
	sk_own = pair.second;

	elgamal->setKey(pk_own, sk_own);
}

/*
*		Store enrollment of sensor in table
*/
void Server::store_table(tuple<int, shared_ptr<Template_enc>, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>>> enrollment) {
	table.add_entry(get<0>(enrollment), get<1>(enrollment), get<2>(enrollment).first, get<2>(enrollment).second);
}


/*
*		Fetch template from table
*/
shared_ptr<Template_enc> Server::fetch_template(int u) {
	return table.get_T_enc(u);
}

/*
*		Compare [[S]]  with threshold t resulting in [[vec_C]]
*/
vector<shared_ptr<AsymmetricCiphertext>> Server::compare(shared_ptr<AsymmetricCiphertext> S_enc, biginteger t, biginteger max_S) {
	vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc;

	elgamal->setKey(pk_shared);

	auto g = dlog->getGenerator();
	biginteger q = dlog->getOrder();

	auto g_t = dlog->exponentiate(g.get(), t);

	//first compute and encrypt g^-t
	shared_ptr<GroupElement> g_min_t = dlog->getInverse(g_t.get());
	GroupElementPlaintext p_g_min_t(g_min_t);
  shared_ptr<AsymmetricCiphertext> c_g_min_t = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_g_min_t));

	//cout << "g^-t: " << ((OpenSSLZpSafePrimeElement *)g_min_t.get())->getElementValue() << endl;

	for(biginteger i=0; i<=max_S-t; i++) {
		//first compute t+i
		biginteger t_plus_i = t+i;

		//compute g^-(t+i) = g^(-t-i) and encrypt
		auto g_t_plus_i = dlog->exponentiate(g.get(), t_plus_i);
		shared_ptr<GroupElement> g_min_t_plus_i = dlog->getInverse(g_t_plus_i.get());
		GroupElementPlaintext p_g_min_t_plus_i(g_min_t_plus_i);
		shared_ptr<AsymmetricCiphertext> c_g_min_t_plus_i = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_g_min_t_plus_i));

		//multiply [[g^S]] * [[g^(t-i)]] = [[g^(S-t-i)]]
		shared_ptr<AsymmetricCiphertext> result = elgamal->multiply(S_enc.get(), c_g_min_t_plus_i.get());

		/*//first compute and encrypt g^-i
		auto g_i = dlog->exponentiate(g.get(), i);
		shared_ptr<GroupElement> g_min_i = dlog->getInverse(g_i.get());

		//cout << "g^-i: " << ((OpenSSLZpSafePrimeElement *)g_min_i.get())->getElementValue() << endl;
		GroupElementPlaintext p_g_min_i(g_min_i);
	  shared_ptr<AsymmetricCiphertext> c_g_min_i = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_g_min_i));

		//multiply g^S * g^-t * g^-i = g^(S-t-i)
		shared_ptr<AsymmetricCiphertext> result = elgamal->multiply(S_enc.get(), c_g_min_t.get());
		result = elgamal->multiply(result.get(), c_g_min_i.get());*/

		//finally blind the result with random value r
		auto id = dlog->getIdentity();
		GroupElementPlaintext p_id(id);
		shared_ptr<AsymmetricCiphertext> result_blind = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_id));
		biginteger r = getRandomInRange(0, q-1, get_seeded_prg().get());

		while(r > 0) {
			if(r & 1) {
					result_blind = elgamal->multiply(result_blind.get(), result.get());
			}

			result = elgamal->multiply(result.get(), result.get());
			r >>= 1;
		}

		/*biginteger r = getRandomInRange(0, q-1, get_seeded_prg().get());
		auto g_r = dlog->exponentiate(g.get(), r);
		GroupElementPlaintext p_g_r(g_r);
		shared_ptr<AsymmetricCiphertext> c_g_r = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_g_r));
		result = elgamal->multiply(result.get(), c_g_r.get());*/

		//save result in C_enc
		vec_C_enc.push_back(result_blind);
	}

	return vec_C_enc;
}

/*
*		Permute [[C]]
*/
vector<shared_ptr<AsymmetricCiphertext>> Server::permute(vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc) {
	unsigned seed = chrono::system_clock::now().time_since_epoch().count();
	shuffle(vec_C_enc.begin(), vec_C_enc.end(), default_random_engine(seed));

	return vec_C_enc;
}

/*
*		Fetch key pair ([[k]], AES_k(1)) corresponding to u from table
*/
pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> Server::fetch_key_pair(int u) {
	return table.get_key_pair(u);
}

/*
*		Compute [[vec_B]] by multipling [[C]] and [[k]] element-wise
*/
vector<shared_ptr<AsymmetricCiphertext>> Server::calc_vec_B_enc(vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc2, shared_ptr<AsymmetricCiphertext> K_enc2) {
	vector<shared_ptr<AsymmetricCiphertext>> B_enc2;

	for(shared_ptr<AsymmetricCiphertext> C_i_enc2 : vec_C_enc2) {
		auto start = chrono::steady_clock::now();
		shared_ptr<AsymmetricCiphertext> B_i_enc2 = elgamal->multiply((ElGamalOnGroupElementCiphertext*) C_i_enc2.get(), (ElGamalOnGroupElementCiphertext*) K_enc2.get());
		auto end = chrono::steady_clock::now();
		//cout << "Time elapsed by computing [[C]]*[[k]] in us: " << chrono::duration_cast<chrono::microseconds>(end-start).count() << endl;
		B_enc2.push_back(B_i_enc2);
	}

	return B_enc2;
}

/*
*	Partial decryption step
* 	[[vec_B]] is partially decrypted to [vec_B]
*	D1(c1, c2) = (c1^k1, c2)
*/
vector<shared_ptr<AsymmetricCiphertext>> Server::D1(vector<shared_ptr<AsymmetricCiphertext>> vec_B_enc) {
	vector<shared_ptr<AsymmetricCiphertext>> vec_B_enc2;

	for(shared_ptr<AsymmetricCiphertext> B_i_enc : vec_B_enc) {
		shared_ptr<GroupElement> b1_prime = dlog->exponentiate(((ElGamalOnGroupElementCiphertext*) B_i_enc.get())->getC1().get(), ((ElGamalPrivateKey*) sk_own.get())->getX());
		ElGamalOnGroupElementCiphertext B_i_enc2 = ElGamalOnGroupElementCiphertext(b1_prime, ((ElGamalOnGroupElementCiphertext*) B_i_enc.get())->getC2());
		vec_B_enc2.push_back(make_shared<ElGamalOnGroupElementCiphertext>(B_i_enc2));
	}

	return vec_B_enc2;
}

/*
*		Return table size
*/
int Server::size_table() {
	return table.size();
}

/*
*		Test function calc_vec_B_enc
*/
void Server::test_calc_vec_B_enc() {
	auto g = dlog->getGenerator();

	vector<shared_ptr<AsymmetricCiphertext>> vec;

	for(int i=0; i<3; i++) {
		auto x = dlog->exponentiate(g.get(), i);
  	GroupElementPlaintext p1(x);
		shared_ptr<AsymmetricCiphertext> cipher1 = elgamal->encrypt(make_shared<GroupElementPlaintext>(p1));
		vec.push_back(cipher1);
	}

	cout << "size of [C]: " << vec.size() << endl;

	auto K = dlog->exponentiate(g.get(), 5);
	GroupElementPlaintext p2(K);
	shared_ptr<AsymmetricCiphertext> cipher2 = elgamal->encrypt(make_shared<GroupElementPlaintext>(p2));

	vector<shared_ptr<AsymmetricCiphertext>> keys = calc_vec_B_enc(vec, cipher2);

	cout << "size of [B]: " << keys.size() << endl;
}

/*
*		Test function compare
*/
void Server::test_compare(biginteger t, biginteger max_S) {
	auto g = dlog->getGenerator();

	cout << "t: " << t << endl;
	cout << "max_S: " << max_S << endl << endl;

	for(int i=0; i<max_S; i++) {
		cout << "S: " << i << endl;

		biginteger S = i;

		auto g_S = dlog->exponentiate(g.get(), S);
		GroupElementPlaintext p_g_S(g_S);
		shared_ptr<AsymmetricCiphertext> c_g_S = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_g_S));

		vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc = compare(c_g_S, t, max_S);

		//test if there's a C_i that equals 1 when decrypted
		for(shared_ptr<AsymmetricCiphertext> C_i_enc : vec_C_enc) {
			shared_ptr<Plaintext> C_i = elgamal->decrypt(C_i_enc.get());
			cout << "C_i: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)C_i.get())->getElement()).get())->getElementValue() << endl;
		}

		cout << endl;
	}
}

/*
*		Test function permute
*/
void Server::test_permute(biginteger S, biginteger t, biginteger max_s) {
	auto g = dlog->getGenerator();

	auto g_S = dlog->exponentiate(g.get(), S);
	GroupElementPlaintext p_g_S(g_S);
	shared_ptr<AsymmetricCiphertext> c_g_S = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_g_S));

	vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc = compare(c_g_S, t, max_s);

	//print all C_i
	for(shared_ptr<AsymmetricCiphertext> C_i_enc : vec_C_enc) {
		shared_ptr<Plaintext> C_i = elgamal->decrypt(C_i_enc.get());
		cout << "C_i: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)C_i.get())->getElement()).get())->getElementValue() << endl;
	}

	cout << endl;

	vector<shared_ptr<AsymmetricCiphertext>> vec_C_enc_prime = permute(vec_C_enc);

	//print all C_i when [[C]] has been permuted
	for(shared_ptr<AsymmetricCiphertext> C_i_enc_prime : vec_C_enc_prime) {
		shared_ptr<Plaintext> C_i_prime = elgamal->decrypt(C_i_enc_prime.get());
		cout << "C_i': " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)C_i_prime.get())->getElement()).get())->getElementValue() << endl;
	}
}

/*
*		Test function D1
*/
shared_ptr<ElGamalOnGroupElementCiphertext> Server::test_D1(shared_ptr<AsymmetricCiphertext> cipher) {
	shared_ptr<GroupElement> c_1_prime = dlog->exponentiate(((ElGamalOnGroupElementCiphertext*) cipher.get())->getC1().get(), ((ElGamalPrivateKey*) sk_own.get())->getX());
	return make_shared<ElGamalOnGroupElementCiphertext>(ElGamalOnGroupElementCiphertext(c_1_prime, ((ElGamalOnGroupElementCiphertext*) cipher.get())->getC2()));
}

int Server::usage() {
	cout << "Usage: " << endl;
	cout << "*	Semi-honest protocol with key release: ./server | ./server sh" << endl;
	cout << "*	Malicious protocol with key release: ./server mal" << endl;

	return 0;
}

int Server::main_sh() {
	try {
		//First set up channel
		boost::asio::io_service io_service;

		SocketPartyData server = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8000);
		SocketPartyData sensor = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8001);

		channel = make_shared<CommPartyTCPSynced>(io_service, server, sensor);

		boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));

		//Join channel
		channel->join(500, 5000);
		cout << "channel established" << endl;

		//First send public key
		send_pk();

		//Receive public key from Sensor
		shared_ptr<PublicKey> pk_ss = recv_pk();

		//Set shared public keys
		key_setup(pk_ss);

		//Receive enrollment parameters from sensor
		string u = recv_msg(); //receive u
		cout << "u: " << u << endl;
		shared_ptr<AsymmetricCiphertext> test = recv_elgamal_msg();

		shared_ptr<Template_enc> T_enc = recv_template(); //receive [[T_u]]

		//shared_ptr<SymmetricCiphertext> aes_k_1 = recv_aes_msg();
		//send_aes_msg(aes_k_1);

		auto com_r = act_p2(3, 5);
		auto com_x = ic_p2();

		io_service.stop();
		t.join();
	} catch (const logic_error& e) {
		// Log error message in the exception object
		cerr << e.what();
	}


	return 0;
}

int Server::main_mal() {
	cout << "not yet implemented" << endl;
	return 0;
}

int main(int argc, char* argv[]) {
	Server sv = Server("dlog_params.txt");

	cout << "test"  << endl;

	if(argc == 1) {
		return sv.main_sh();
	} else if(argc == 2) {
	string arg(argv[1]);
		if(arg == "sh") {
			return sv.main_sh();
		} else if(arg == "mal") {
			return sv.main_mal();
		}
	} else {
		return sv.usage();
	}

	return 0;
}
