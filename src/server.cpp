/*
*	Created using libscapi (see https://crypto.biu.ac.il/SCAPI/)
*	Authors: Ruth Scholten
*/

#include <iostream>
#include <vector>
#include <algorithm>
#include <stdlib.h>
#include <array>
#include <chrono>

#include "../include/server.hpp"

using namespace std;

Server::Server() {
	//Intialize encryption objects
	aes = make_shared<OpenSSLCTREncRandomIV>("AES");

	dlog = make_shared<OpenSSLDlogECF2m>("../../libscapi/include/configFiles/NISTEC.txt", "K-233");
	//dlog = make_shared<OpenSSLDlogECFp>("B-163");
	elgamal = make_shared<ElGamalOnGroupElementEnc>(dlog);

	//Generate and set ElGamal keypair
	auto start = std::chrono::high_resolution_clock::now();

	auto pair = elgamal->generateKey();

	pk_own = pair.first;
	sk_own = pair.second;

	elgamal->setKey(pk_own, sk_own);

	auto end = std::chrono::high_resolution_clock::now();

	cout << "ElGamal setup: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << endl;
}

/*
*	Store enrollment of sensor in table (with signatures for malicious protocol)
*/
void Server::store_table(int u, shared_ptr<Template_enc> T_enc, shared_ptr<AsymmetricCiphertext> c_k, shared_ptr<SymmetricCiphertext> aes_k_1, Signature sig_m, Signature sig_n, shared_ptr<GroupElement> y) {
	table.add_entry(u, T_enc, c_k, aes_k_1, sig_m, sig_n, y);
}

/*
*	Store enrollment parameters of sensor in table (without signatures for semi-honest protocol)
*/
void Server::store_table(int u, shared_ptr<Template_enc> T_enc, shared_ptr<AsymmetricCiphertext> c_k, shared_ptr<SymmetricCiphertext> aes_k_1) {
	Signature sig_m;
	Signature sig_n;
	shared_ptr<GroupElement> y;

	store_table(u, T_enc, c_k, aes_k_1, sig_m, sig_n, y);
}

/*
*	Fetch template from table
*/
shared_ptr<Template_enc> Server::fetch_template(int u) {
	return table.get_T_enc(u);
}

/*
*	Fetch \sigma(m) from table
*/
Signature Server::fetch_sig_m(int u) {
	return table.get_sig_m(u);
}

/*
*	Fetch \sigma(n) from table
*/
Signature Server::fetch_sig_n(int u) {
	return table.get_sig_n(u);
}

/*
*	Fetch public key for signatures from table
*/
shared_ptr<GroupElement> Server::fetch_y(int u) {
	return table.get_y(u);
}

/*
*
*/
tuple<vector<shared_ptr<AsymmetricCiphertext>>, vector<shared_ptr<AsymmetricCiphertext>>, vector<biginteger>> Server::compare_mal(shared_ptr<AsymmetricCiphertext> S_enc, biginteger t, biginteger max_S) {
	vector<shared_ptr<AsymmetricCiphertext>> C_enc;
	vector<shared_ptr<AsymmetricCiphertext>> C_enc_no_r_sv;
	vector<biginteger> blind_vals;

	elgamal->setKey(pk_shared);

	auto g = dlog->getGenerator();
	biginteger q = dlog->getOrder();

	biginteger j = max_S - t;

	for (int i = 0; i <= j; i++) {
		biginteger x = bct_p1();

		//compute g^(-t-i)
		biginteger min_t_min_i = q - t - i;
		auto g_min_t_min_i = dlog->exponentiate(g.get(), min_t_min_i);

		//encrypt g^(-t-i) using x as randomness
		GroupElementPlaintext p_g_min_t_min_i(g_min_t_min_i);
		shared_ptr<AsymmetricCiphertext> c_g_min_t_min_i = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_g_min_t_min_i), x);

		//multiply [[g^S]] * [[g^(t-i)]] = [[g^(S-t-i)]]
		shared_ptr<AsymmetricCiphertext> result = elgamal->multiply(S_enc.get(), c_g_min_t_min_i.get(), x);

		//save result in C_enc_no_r_sv
		C_enc_no_r_sv.push_back(result);

		//finally blind result with r obtained by the Augmented Coin Tossing protocol
		pair<biginteger, biginteger> acointoss = act_p1(2,6);
		biginteger r = acointoss.first;
		blind_vals.push_back(r);

		auto c1 = ((ElGamalOnGroupElementCiphertext*)result.get())->getC1();
		auto c2 = ((ElGamalOnGroupElementCiphertext*)result.get())->getC2();

		auto c1_blind = dlog->exponentiate(c1.get(), r);
		auto c2_blind = dlog->exponentiate(c2.get(), r);

		shared_ptr<AsymmetricCiphertext> result_blind = make_shared<ElGamalOnGroupElementCiphertext>(ElGamalOnGroupElementCiphertext(c1_blind, c2_blind));

		//save result in C_enc
		C_enc.push_back(result_blind);
	}

	return make_tuple(C_enc, C_enc_no_r_sv, blind_vals);
}

/*
*	Prove correctness of comparison operation
*/
void Server::prove_compare(vector<biginteger> r, vector<shared_ptr<AsymmetricCiphertext>> C_enc, vector<shared_ptr<AsymmetricCiphertext>> C_enc_prime_prime) {

	for (int i = 0; i <= max_S - t; i++) {
		vector<shared_ptr<GroupElement>> c;
		vector<shared_ptr<GroupElement>> c_prime_prime;

		auto c1 = ((ElGamalOnGroupElementCiphertext*)C_enc[i].get())->getC1();
		auto c1_prime_prime = ((ElGamalOnGroupElementCiphertext*)C_enc_prime_prime[i].get())->getC1();

		auto c2 = ((ElGamalOnGroupElementCiphertext*)C_enc[i].get())->getC2();
		auto c2_prime_prime = ((ElGamalOnGroupElementCiphertext*)C_enc_prime_prime[i].get())->getC2();

		c.push_back(c1);
		c.push_back(c2);

		c_prime_prime.push_back(c1_prime_prime);
		c_prime_prime.push_back(c2_prime_prime);

		//add com(r), etc

		zkpk_prove(r[i], c, c_prime_prime);
	}


}

/*
*	Compare [[S]] with threshold t resulting in [[C]]
*/
vector<shared_ptr<AsymmetricCiphertext>> Server::compare(shared_ptr<AsymmetricCiphertext> S_enc, biginteger t, biginteger max_S) {
	vector<shared_ptr<AsymmetricCiphertext>> C_enc;

	elgamal->setKey(pk_shared);

	auto g = dlog->getGenerator();
	biginteger q = dlog->getOrder();

	for(biginteger i=0; i<=max_S-t; i++) {
		//compute g^(-t-i)
		biginteger min_t_min_i = q - t - i;
		auto g_min_t_min_i = dlog->exponentiate(g.get(), min_t_min_i);

		//encrypt g^(-t-i) using x as randomness
		GroupElementPlaintext p_g_min_t_min_i(g_min_t_min_i);
		shared_ptr<AsymmetricCiphertext> c_g_min_t_min_i = elgamal->encrypt(make_shared<GroupElementPlaintext>(p_g_min_t_min_i));

		//multiply [[g^S]] * [[g^(t-i)]] = [[g^(S-t-i)]]
		shared_ptr<AsymmetricCiphertext> result = elgamal->multiply(S_enc.get(), c_g_min_t_min_i.get());

		//finally blind the result with random value r
		biginteger r = getRandomInRange(0, q-1, get_seeded_prg().get());

		auto c1 = ((ElGamalOnGroupElementCiphertext*)result.get())->getC1();
		auto c2 = ((ElGamalOnGroupElementCiphertext*)result.get())->getC2();

		auto c1_blind = dlog->exponentiate(c1.get(), r);
		auto c2_blind = dlog->exponentiate(c2.get(), r);

		shared_ptr<AsymmetricCiphertext> result_blind = make_shared<ElGamalOnGroupElementCiphertext>(ElGamalOnGroupElementCiphertext(c1_blind, c2_blind));

		//save result in C_enc
		C_enc.push_back(result_blind);
	}

	return C_enc;
}

/*
*	Permute [[C]]
*/
tuple<vector<shared_ptr<AsymmetricCiphertext>>, vector<biginteger>, vector<vector<int>>> Server::permute(vector<shared_ptr<AsymmetricCiphertext>> C_enc) {
	int k = C_enc.size();

	vector<shared_ptr<AsymmetricCiphertext>> C_enc_prime;
	vector<biginteger> A_0(k, 0);

	auto g = dlog->getGenerator();
	biginteger q = dlog->getOrder();

	//Randomly generate permutation matrix A_{ij}
	vector<vector<int>> A = permutation_matrix(k);

	for (int i = 0; i < k; i++) {
		A_0[i] = getRandomInRange(0, q - 1, get_seeded_prg().get());

		auto vec_g_prime = dlog->exponentiate(g.get(), A_0[i]);
		auto vec_m_prime = dlog->exponentiate(((ElGamalPublicKey*)pk_shared.get())->getH().get(), A_0[i]);

		for (int j = 0; j < k; j++) {
			if (A[i][j] == 1) {
				vec_g_prime = dlog->multiplyGroupElements(vec_g_prime.get(), ((ElGamalOnGroupElementCiphertext*)C_enc[j].get())->getC1().get());
				vec_m_prime = dlog->multiplyGroupElements(vec_m_prime.get(), ((ElGamalOnGroupElementCiphertext*)C_enc[j].get())->getC2().get());
			}
		}

		C_enc_prime.push_back(make_shared<ElGamalOnGroupElementCiphertext>(vec_g_prime, vec_m_prime));
	}

	return make_tuple(C_enc_prime, A_0, A);
}

/*
*	Prove permutation function has been executed in a semi-honest fashion
*	Implementation of first protocol paper in Furukawa: Efficient and Verifiable Shuffling and Shuffle-Decryption
*/
void Server::prove_permutation(vector<shared_ptr<AsymmetricCiphertext>> C_enc, vector<shared_ptr<AsymmetricCiphertext>> C_enc_prime, vector<biginteger> A_0, vector<vector<int>> perm_matrix) {
	auto g = dlog->getGenerator();
	biginteger q = dlog->getOrder();
	auto gen = get_seeded_prg();

	int k = C_enc_prime.size();
	int k5 = k + 5;

	//Receive F_k from verifier
	vector<shared_ptr<GroupElement>> f = recv_vec_group_element();

	vector<biginteger> a(k + 5, 0);
	vector<vector<biginteger>> A(k + 1, a);

	//Generate A_v0 and A_v' for v=-4,...,k and A_-1i for i=1,...,k
	vector<biginteger> A_v0(k5, 0);
	vector<biginteger> A_v_prime(k5, 0);
	vector<biginteger> A_min_1(k, 0);

	for (int i = 0; i < k5; i++) {
		A_v0[i] = getRandomInRange(0, q-1, gen.get());
		A_v_prime[i] = getRandomInRange(0, q-1, gen.get());
	}

	for (int i = 0; i < k; i++) {
		A_min_1[i] = getRandomInRange(0, q-1, gen.get());
	}

	A[0] = A_v0;

	//Compute A_-2i, A_-3i, A_4i
	for (int i = 0; i < k; i++) {
		biginteger A_min_2i;
		biginteger A_min_3i;
		biginteger A_min_4i;

		for (int j = 0; j < k; j++) {
			A_min_2i = mod(A_min_2i + 3 * A_v0[j + 5] * A_v0[j + 5] * perm_matrix[i][j], q);
			A_min_3i = mod(A_min_3i + 3 * A_v0[j + 5] * perm_matrix[i][j], q);
			A_min_4i = mod(A_min_4i + 2 * A_v0[j + 5] * perm_matrix[i][j], q);
		}

		vector<biginteger> column(k + 5, 0);
		column[0] = A_min_4i;
		column[1] = A_min_3i;
		column[2] = A_min_2i;
		column[3] = A_min_1[i];
		column[4] = A_0[i];

		for (int v = 0; v < k; v++) {
			column[v + 5] = perm_matrix[i][v];
		}

		A[i + 1] = column;
	}

	//print_permutation_matrix(A);

	//Compute f_micro', f_tilde_0', g_0', m_0', w and w_dot
	vector<shared_ptr<GroupElement>> f_prime;
	shared_ptr<GroupElement> f_tilde_0_prime = dlog->getIdentity();
	shared_ptr<GroupElement> g_0_prime = dlog->exponentiate(g.get(), A_v0[0+4]);
	shared_ptr<GroupElement> m_0_prime = dlog->exponentiate(((ElGamalPublicKey*)pk_shared.get())->getH().get(), A_v0[0+4]);
	biginteger w = (A_v0[-2 + 4] + A_v_prime[-3 + 4]) * -1;
	biginteger w_dot = A_v0[-4 + 4]*-1;

	for (int micro = 0; micro <= k; micro++) {
		auto element = dlog->getIdentity();

		for (int v = 0; v < k5; v++) {
			element = dlog->multiplyGroupElements(element.get(), dlog->exponentiate(f[v].get(), A[micro][v]).get());
		}

		f_prime.push_back(element);
	}

	for (int v = 0; v < k5; v++) {
		f_tilde_0_prime = dlog->multiplyGroupElements(f_tilde_0_prime.get(), dlog->exponentiate(f[v].get(), A_v_prime[v]).get());
	}

	for (int v = 0; v < k; v++) {
		auto g_v = ((ElGamalOnGroupElementCiphertext*)C_enc[v].get())->getC1();
		auto m_v = ((ElGamalOnGroupElementCiphertext*)C_enc[v].get())->getC2();

		g_0_prime = dlog->multiplyGroupElements(g_0_prime.get(), dlog->exponentiate(g_v.get(), A_v0[v+5]).get());
		m_0_prime = dlog->multiplyGroupElements(m_0_prime.get(), dlog->exponentiate(m_v.get(), A_v0[v+5]).get());
	}

	for (int j = 0; j < k; j++) {
		w = mod(w + A_v0[j+5]*A_v0[j+5]*A_v0[j+5], q);
		w_dot = mod(w_dot + A_v0[j+5]*A_v0[j+5], q);
	}

	//The prover sends the following elements as commitment to the verifier
	send_group_element(g_0_prime);
	send_group_element(m_0_prime);
	send_group_element(f_tilde_0_prime);
	send_vec_group_element(f_prime);
	send_biginteger(w);
	send_biginteger(w_dot);

	//Receive challenge from verifier
	vector<biginteger> c = recv_vec_biginteger();

	//Compute response
	vector<biginteger> r(k + 5, 0);
	vector<biginteger> r_prime(k+5, 0);

	for (int v = 0; v < k5; v++) {
		for (int micro = 0; micro <= k; micro++) {
			r[v] = mod(r[v] + A[micro][v] * c[micro], q);
		}
	}

	for (int v = 0; v < k5; v++) {
		r_prime[v] = A_v_prime[v];

		for (int i = 1; i <= k; i++) {
			r_prime[v] = mod(r_prime[v] + (A[i][v] * c[i]*c[i]), q);
		}
	}

	//Send respone to verifier
	send_vec_biginteger(r);
	send_vec_biginteger(r_prime);
}

/*
*	Prove permutation function has been executed in a semi-honest fashion
*	Implementation of protocol in paper Furukawa: An Efficient Scheme for Proving a Shuffle
*/
void Server::prove_permutation2(vector<shared_ptr<AsymmetricCiphertext>> C_enc, vector<shared_ptr<AsymmetricCiphertext>> C_enc_prime, vector<biginteger> vec_r, vector<vector<int>> A) {
	auto g = dlog->getGenerator();
	biginteger q = dlog->getOrder();
	auto gen = get_seeded_prg();

	int n = C_enc.size();

	//The prover generates randomly \tilde{g}, {\tilde{g}_i} for 0 <= i < n and sends these to the verifier
	auto g_tilde = dlog->createRandomGenerator();
	vector<shared_ptr<GroupElement>> vec_g_tilde;

	for (int i = 0; i < n; i++) {
		vec_g_tilde.push_back(dlog->exponentiate(g_tilde.get(), getRandomInRange(0, q-1, gen.get())));
	}

	send_group_element(g_tilde);
	send_vec_group_element(vec_g_tilde);

	//1. Prover generates the following random integers \in Z_q:
	biginteger sigma = getRandomInRange(0, q - 1, gen.get());
	biginteger rho = getRandomInRange(0, q - 1, gen.get());
	biginteger tau = getRandomInRange(0, q - 1, gen.get());
	biginteger alpha = getRandomInRange(0, q - 1, gen.get());
	vector<biginteger> vec_alpha;

	for (int i = 0; i < n; i++) {
		vec_alpha.push_back(getRandomInRange(0, q - 1, gen.get()));
	}

	biginteger lambda = getRandomInRange(0, q - 1, gen.get());

	vector<biginteger> vec_lambda;

	for (int i = 0; i < n; i++) {
		vec_lambda.push_back(getRandomInRange(0, q - 1, gen.get()));
	}

	//2. Prover computes the following elements \in Z*_p:
	auto t = dlog->exponentiate(g.get(), tau);
	//cout << "t: " << ((OpenSSLZpSafePrimeElement*)t.get())->getElementValue() << endl;
	auto v = dlog->exponentiate(g.get(), rho);
	auto w = dlog->exponentiate(g.get(), sigma);
	auto u = dlog->exponentiate(g.get(), lambda);
	vector<shared_ptr<GroupElement>> vec_u;

	for (int i = 0; i < n; i++) {
		vec_u.push_back(dlog->exponentiate(g.get(), vec_lambda[i]));
	}

	auto g_tilde_prime = dlog->exponentiate(g_tilde.get(), alpha);
	auto g_prime = dlog->exponentiate(g.get(), alpha);
	auto m_prime = dlog->exponentiate(((ElGamalPublicKey*) pk_shared.get())->getH().get(), alpha);
	biginteger exp_v_dot = tau * lambda + rho * alpha;
	biginteger exp_w_dot = sigma * alpha;

	for (int j = 0; j < n; j++) {
		g_tilde_prime = dlog->multiplyGroupElements(g_tilde_prime.get(), dlog->exponentiate(vec_g_tilde[j].get(), vec_alpha[j]).get());
		g_prime = dlog->multiplyGroupElements(g_prime.get(), dlog->exponentiate(((ElGamalOnGroupElementCiphertext*) C_enc[j].get())->getC1().get(), vec_alpha[j]).get());
		m_prime = dlog->multiplyGroupElements(m_prime.get(), dlog->exponentiate(((ElGamalOnGroupElementCiphertext*) C_enc[j].get())->getC2().get(), vec_alpha[j]).get());
		exp_v_dot = mod(exp_v_dot + vec_alpha[j]* vec_alpha[j]* vec_alpha[j], q);
		exp_w_dot = mod(exp_w_dot + vec_alpha[j]*vec_alpha[j], q);
	}

	auto v_dot = dlog->exponentiate(g.get(), exp_v_dot);
	auto w_dot = dlog->exponentiate(g.get(), exp_w_dot);

	vector<shared_ptr<GroupElement>> vec_g_tilde_prime;
	vector<shared_ptr<GroupElement>> vec_t_dot;
	vector<shared_ptr<GroupElement>> vec_v_dot;
	vector<shared_ptr<GroupElement>> vec_w_dot;

	for (int i = 0; i < n; i++) {
		auto vec_g_tilde_prime_elem = dlog->exponentiate(g_tilde.get(), vec_r[i]);
		biginteger exp_vec_t_dot = tau * vec_lambda[i];
		biginteger exp_vec_v_dot = rho * vec_r[i];
		biginteger exp_vec_w_dot = sigma * vec_r[i];

		for (int j = 0; j < n; j++) {
			vec_g_tilde_prime_elem = dlog->multiplyGroupElements(vec_g_tilde_prime_elem.get(), dlog->exponentiate(vec_g_tilde[j].get(), A[i][j]).get());
			exp_vec_t_dot = mod(exp_vec_t_dot + (3 * vec_alpha[j] * A[i][j]), q);
			exp_vec_v_dot = mod(exp_vec_v_dot + (3*vec_alpha[j]*vec_alpha[j] * A[i][j]), q);
			exp_vec_w_dot = mod(exp_vec_w_dot + (2*vec_alpha[j]*A[i][j]), q);
		}

		vec_g_tilde_prime.push_back(vec_g_tilde_prime_elem);
		vec_t_dot.push_back(dlog->exponentiate(g.get(), exp_vec_t_dot));
		vec_v_dot.push_back(dlog->exponentiate(g.get(), exp_vec_v_dot));
		vec_w_dot.push_back(dlog->exponentiate(g.get(), exp_vec_w_dot));
	}

	//3. Prover sends t, v, w, u, {vec_u}, {\tilde{g}_i}, \tilde{g}', g', m', {\dot{t}_i}, {\dot{v}_i}, {\dot{w}_i}, \dot{w} (i=1,...,n) to the verifier
	send_group_element(t);
	send_group_element(v);
	send_group_element(w);
	send_group_element(u);
	send_vec_group_element(vec_u);
	send_vec_group_element(vec_g_tilde_prime);
	send_group_element(g_tilde_prime);
	send_group_element(g_prime);
	send_group_element(m_prime);
	send_vec_group_element(vec_t_dot);
	send_vec_group_element(vec_v_dot);
	send_group_element(v_dot);
	send_vec_group_element(vec_w_dot);
	send_group_element(w_dot);

	//Prover receives challenges c and computes s, s_i and \lambda'
	vector<biginteger> c = recv_vec_biginteger();

	biginteger s = alpha;
	vector<biginteger> vec_s(n, 0);
	biginteger lambda_prime = lambda;

	for (int j = 0; j < n; j++) {
		s = mod(s + vec_r[j] * c[j], q);
		lambda_prime = mod(lambda_prime + vec_lambda[j] * c[j]*c[j], q);
	}

	for (int i = 0; i < n; i++) {
		vec_s[i] = vec_alpha[i];

		for (int j = 0; j < n; j++) {
			vec_s[i] = mod(vec_s[i] + A[j][i] * c[j], q);
		}
	}

	send_biginteger(s);
	send_vec_biginteger(vec_s);
	send_biginteger(lambda_prime);
}

/*
*	Fetch key pair ([[k]], AES_k(1)) corresponding to u from table
*/
pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> Server::fetch_key_pair(int u) {
	return table.get_key_pair(u);
}

/*
*	Partial decryption step
* 	[[B]] is partially decrypted to [B]
*	D1(c1, c2) = (c1^k1, c2)
*/
vector<shared_ptr<AsymmetricCiphertext>> Server::D1(vector<shared_ptr<AsymmetricCiphertext>> B_enc) {
	vector<shared_ptr<AsymmetricCiphertext>> B_enc2;

	for(shared_ptr<AsymmetricCiphertext> B_i_enc : B_enc) {
		shared_ptr<GroupElement> b1_prime = dlog->exponentiate(((ElGamalOnGroupElementCiphertext*) B_i_enc.get())->getC1().get(), ((ElGamalPrivateKey*) sk_own.get())->getX());
		ElGamalOnGroupElementCiphertext B_i_enc2 = ElGamalOnGroupElementCiphertext(b1_prime, ((ElGamalOnGroupElementCiphertext*) B_i_enc.get())->getC2());
		B_enc2.push_back(make_shared<ElGamalOnGroupElementCiphertext>(B_i_enc2));
	}

	return B_enc2;
}

/*
*	Prove partial decryption step
*/
void Server::prove_D1(vector<shared_ptr<AsymmetricCiphertext>> B_enc2, vector<shared_ptr<AsymmetricCiphertext>> B_enc) {
	biginteger sk_sv = ((ElGamalPrivateKey*)sk_own.get())->getX();
	auto pk_sv = ((ElGamalPublicKey*)pk_own.get())->getH();

	vector<shared_ptr<GroupElement>> c1_prime;
	vector<shared_ptr<GroupElement>> c1;
	
	//Add first parameter of ElGamal encryption of [B] and [[B]], respectively, to c1' (vector of y's) and c1 (vector of bases)
	for (int i = 0; i < B_enc2.size(); i++) {
		c1_prime.push_back(((ElGamalOnGroupElementCiphertext*)B_enc2[i].get())->getC1());
		c1.push_back(((ElGamalOnGroupElementCiphertext*)B_enc[i].get())->getC1());
	}

	//finally add y2=g^sk_sv and pk_sv to c1' and c1, respectively
	c1_prime.push_back(pk_sv);
	c1.push_back(dlog->getGenerator());

	zkpk_prove(sk_sv, c1_prime, c1);
}

/*
*	Return table size
*/
int Server::size_table() {
	return table.size();
}

/*
*	Test function calc_B_enc
*/
void Server::test_calc_B_enc() {
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

	vector<shared_ptr<AsymmetricCiphertext>> keys = calc_B_enc(vec, cipher2);

	cout << "size of [B]: " << keys.size() << endl;
}

/*
*	Test function compare
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

		vector<shared_ptr<AsymmetricCiphertext>> C_enc = compare(c_g_S, t, max_S);

		//test if there's a C_i that equals 1 when decrypted
		for(shared_ptr<AsymmetricCiphertext> C_i_enc : C_enc) {
			shared_ptr<Plaintext> C_i = elgamal->decrypt(C_i_enc.get());
			cout << "C_i: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)C_i.get())->getElement()).get())->getElementValue() << endl;
		}

		cout << endl;
	}
}

/*
*	Test function permute
*/
void Server::test_permute(int size) {
	auto g = dlog->getGenerator();

	vector<shared_ptr<AsymmetricCiphertext>> vec;

	for (int i = 0; i < size; i++) {
		auto elem = dlog->createRandomElement();
		GroupElementPlaintext p(elem);
		shared_ptr<AsymmetricCiphertext> c = elgamal->encrypt(make_shared<GroupElementPlaintext>(p));
		vec.push_back(c);
	}

	//print all C_i
	for(shared_ptr<AsymmetricCiphertext> elem : vec) {
		shared_ptr<Plaintext> m = elgamal->decrypt(elem.get());
		cout << "Message: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)m.get())->getElement()).get())->getElementValue() << endl;
	}

	cout << endl;

	tuple<vector<shared_ptr<AsymmetricCiphertext>>, vector<biginteger>, vector<vector<int>>> perm = permute(vec);

	//print all C_i when [[C]] has been permuted
	for(shared_ptr<AsymmetricCiphertext> elem : get<0>(perm)) {
		shared_ptr<Plaintext> m = elgamal->decrypt(elem.get());
		cout << "Message': " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)m.get())->getElement()).get())->getElementValue() << endl;
	}
}

/*
*	Test function D1
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

		boost::thread th(boost::bind(&boost::asio::io_service::run, &io_service));

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
		int u_enroll = stoi(recv_msg()); //receive u
		cout << "received enrollment from user u: " << u_enroll << endl;
		shared_ptr<Template_enc> T_enc_enroll = recv_template(); //receive [[T_u]]
		shared_ptr<AsymmetricCiphertext> k_enc_enroll = recv_msg_enc(); //receive [[k]]
		shared_ptr<SymmetricCiphertext> aes_k_1_enroll = recv_aes_msg(); //receive AES_k(1)

		//Store enrollment in table
		store_table(u_enroll, T_enc_enroll, k_enc_enroll, aes_k_1_enroll);

		//Receive identity claim u from sensor
		int u = stoi(recv_msg());
		cout << "received identity claim u: " << u << endl;

		//Fetch T_u from table
		shared_ptr<Template_enc> T_enc = fetch_template(u);

		//Send T_u to sensor
		send_template(T_enc);

		//Receive [[S]] from sensor
		shared_ptr<AsymmetricCiphertext> S_enc = recv_msg_enc();

		//Compare [[S]] with t
		vector<shared_ptr<AsymmetricCiphertext>> C_enc = compare(S_enc, t, max_S);

		//Permute [[C]] to get [[C']]
		tuple<vector<shared_ptr<AsymmetricCiphertext>>, vector<biginteger>, vector<vector<int>>> C_enc_prime = permute(C_enc);

		//Fetch key pair ([[k]], AES_k(1)) from table
		pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> key_pair = fetch_key_pair(u);

		//Multiply elements in [[C]] with [[k]]
		vector<shared_ptr<AsymmetricCiphertext>> B_enc = calc_B_enc(get<0>(C_enc_prime), key_pair.first);

		//Perform partial decryption function D1
		vector<shared_ptr<AsymmetricCiphertext>> B_enc2 = D1(B_enc);

		//Send pair ([B], AES_k(1)) to sensor
		send_vec_enc(B_enc2);
		send_aes_msg(key_pair.second);

		io_service.stop();
		th.join();
	} catch (const logic_error& e) {
		cerr << e.what();
	}

	return 0;
}

int Server::main_mal() {
	try {
		//First set up channel
		boost::asio::io_service io_service;

		SocketPartyData server = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8000);
		SocketPartyData sensor = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8001);

		channel = make_shared<CommPartyTCPSynced>(io_service, server, sensor);

		boost::thread th(boost::bind(&boost::asio::io_service::run, &io_service));

		//Join channel
		channel->join(500, 5000);
		cout << "channel established" << endl;

		auto start_setup = std::chrono::high_resolution_clock::now();

		//First send public key
		send_pk();

		//Receive public key from Sensor
		shared_ptr<PublicKey> pk_ss = recv_pk();

		//Set shared public keys
		key_setup(pk_ss);

		auto end_setup = std::chrono::high_resolution_clock::now();

		//Receive enrollment parameters m and n and signatures \sigma(m) and \sigma(n) from sensor
		auto start_comm1 = std::chrono::high_resolution_clock::now();

		int u_enroll = stoi(recv_msg()); //receive u
		cout << "received enrollment from user u: " << u_enroll << endl;
		shared_ptr<Template_enc> T_enc_enroll = recv_template(); //receive [[T_u]]
		shared_ptr<AsymmetricCiphertext> k_enc_enroll = recv_msg_enc(); //receive [[k]]
		shared_ptr<SymmetricCiphertext> aes_k_1_enroll = recv_aes_msg(); //receive AES_k(1)
		Signature sig_m_enroll = recv_signature(); //receive \sigma(m)
		Signature sig_n_enroll = recv_signature(); //receive \sigma(n)
		shared_ptr<GroupElement> y_enroll = recv_group_element(); //receive public key y

		auto end_comm1 = std::chrono::high_resolution_clock::now();

		//Store enrollment in table
		auto start_store = std::chrono::high_resolution_clock::now();

		store_table(u_enroll, T_enc_enroll, k_enc_enroll, aes_k_1_enroll, sig_m_enroll, sig_n_enroll, y_enroll);

		auto end_store = std::chrono::high_resolution_clock::now();

		//Receive identity claim u from sensor
		auto start_comm2 = std::chrono::high_resolution_clock::now();

		int u = stoi(recv_msg());
		cout << "received identity claim u: " << u << endl;

		auto end_comm2 = std::chrono::high_resolution_clock::now();

		//Fetch T_u, [[k]], AES_k(1), sig(m), sig(n) and y from table
		auto start_fetch = std::chrono::high_resolution_clock::now();

		shared_ptr<Template_enc> T_enc = fetch_template(u);
		pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> key_pair = fetch_key_pair(u);
		Signature sig_m = fetch_sig_m(u);
		Signature sig_n = fetch_sig_n(u);
		shared_ptr<GroupElement> y = fetch_y(u);

		auto end_fetch = std::chrono::high_resolution_clock::now();

		//Send T_u, [[k]], AES_k(1), sig(m) and sig(n) to sensor
		auto start_comm3 = std::chrono::high_resolution_clock::now();

		send_template(T_enc);
		send_msg_enc(key_pair.first);
		send_aes_msg(key_pair.second);
		send_signature(sig_m);
		send_signature(sig_n);
		send_group_element(y);

		cout << "<----(T_u, [[k]], AES_k(1), sig(m), sig(n))----" << endl;

		//Receive [[S]] from sensor
		shared_ptr<AsymmetricCiphertext> S_enc = recv_msg_enc();

		auto end_comm3 = std::chrono::high_resolution_clock::now();

		//Compare [[S]] with t
		auto start_compare = std::chrono::high_resolution_clock::now();

		tuple<vector<shared_ptr<AsymmetricCiphertext>>, vector<shared_ptr<AsymmetricCiphertext>>, vector<biginteger>> comparison_malicious = compare_mal(S_enc, t, max_S);
		vector<shared_ptr<AsymmetricCiphertext>> C_enc = get<0>(comparison_malicious);
		vector<shared_ptr<AsymmetricCiphertext>> C_enc_prime_prime = get<1>(comparison_malicious);
		vector<biginteger> r = get<2>(comparison_malicious);

		auto end_compare = std::chrono::high_resolution_clock::now();

		//Send [[C]] to sensor
		auto start_comm4 = std::chrono::high_resolution_clock::now();

		send_vec_enc(C_enc);

		auto end_comm4 = std::chrono::high_resolution_clock::now();

		cout << "<-------[[C]]------" << endl;
			 
		//Prove comparison operation
		auto start_prove_compare = std::chrono::high_resolution_clock::now();

		prove_compare(r, C_enc, C_enc_prime_prime);

		auto end_prove_compare = std::chrono::high_resolution_clock::now();

		cout << "<-------ZK-Proof Comparison------>" << endl;

		//Permute [[C]] to get [[C']]
		auto start_permute = std::chrono::high_resolution_clock::now();

		tuple<vector<shared_ptr<AsymmetricCiphertext>>, vector<biginteger>, vector<vector<int>>> permutation = permute(C_enc);

		auto end_permute = std::chrono::high_resolution_clock::now();

		vector<shared_ptr<AsymmetricCiphertext>> C_enc_prime = get<0>(permutation);
		vector<biginteger> A_0 = get<1>(permutation);
		vector<vector<int>> A = get<2>(permutation);

		//Send [[C']] to sensor
		auto start_comm5 = std::chrono::high_resolution_clock::now();

		send_vec_enc(C_enc_prime);

		auto end_comm5 = std::chrono::high_resolution_clock::now();

		cout << "<----[[C']]----" << endl;

		//Prove permutation function \pi([[C]] = [[C']]
		auto start_prove_permute = std::chrono::high_resolution_clock::now();

		prove_permutation(C_enc, C_enc_prime, A_0, A);

		auto end_prove_permute = std::chrono::high_resolution_clock::now();

		cout << "<------ZK-Proof Permutation------>" << endl;

		//Multiply elements in [[C]] with [[k]]
		auto start_B = std::chrono::high_resolution_clock::now();

		vector<shared_ptr<AsymmetricCiphertext>> B_enc = calc_B_enc(C_enc_prime, key_pair.first);

		auto end_B = std::chrono::high_resolution_clock::now();

		cout << "[[B]] = [[C']] + [[k]]" << endl;

		//Perform partial decryption function D1
		auto start_D1 = std::chrono::high_resolution_clock::now();

		vector<shared_ptr<AsymmetricCiphertext>> B_enc2 = D1(B_enc);

		auto end_D1 = std::chrono::high_resolution_clock::now();

		cout << "D1([[B]]) = [B]" << endl;

		//Send [B] to sensor
		auto start_comm6 = std::chrono::high_resolution_clock::now();

		send_vec_enc(B_enc2);

		auto end_comm6 = std::chrono::high_resolution_clock::now();

		cout << "<-------[B]--------" << endl;

		//Prove partial decryption D1
		auto start_prove_D1 = std::chrono::high_resolution_clock::now();

		prove_D1(B_enc2, B_enc);

		auto end_prove_D1 = std::chrono::high_resolution_clock::now();

		cout << "<--------ZK-Proof Partial Decryption ------->" << endl;


		//Print elapsed time
		auto time_setup = chrono::duration_cast<chrono::microseconds>(end_setup - start_setup).count();
		auto time_store = chrono::duration_cast<chrono::microseconds>(end_store - start_store).count();
		auto time_fetch = chrono::duration_cast<chrono::microseconds>(end_fetch - start_fetch).count();
		auto time_compare = chrono::duration_cast<chrono::microseconds>(end_compare - start_compare).count();
		auto time_prove_compare = chrono::duration_cast<chrono::microseconds>(end_prove_compare - start_prove_compare).count();
		auto time_permute = chrono::duration_cast<chrono::microseconds>(end_permute - start_permute).count();
		auto time_prove_permute = chrono::duration_cast<chrono::microseconds>(end_prove_permute - start_prove_permute).count();
		auto time_B = chrono::duration_cast<chrono::microseconds>(end_B - start_B).count();
		auto time_D1 = chrono::duration_cast<chrono::microseconds>(end_D1 - start_D1).count();
		auto time_prove_D1 = chrono::duration_cast<chrono::microseconds>(end_prove_D1 - start_prove_D1).count();
		auto time_comm = chrono::duration_cast<chrono::microseconds>(end_comm1 - start_comm1 + end_comm2 - start_comm2 + end_comm3 - start_comm3 + end_comm4 - start_comm4 + end_comm5 - start_comm5 + end_comm6 - start_comm6).count();
		
		auto time_total = time_setup + time_store + time_fetch + time_compare + time_prove_compare + time_permute + time_prove_permute + time_B + time_D1 + time_prove_D1 + time_comm;
		auto time_alpha = time_compare + time_prove_compare + time_permute + time_B + time_D1 + time_prove_D1;

		cout << endl;
		cout << "Elapsed time in us: " << endl;
		cout << "Shared key setup: " << time_setup << endl;
		cout << "Store in table: " << time_store << endl;
		cout << "Fetch from table: " << time_fetch << endl;
		cout << "Comparison: " << time_compare << endl;
		cout << "Prove comparison: " << time_prove_compare << endl;
		cout << "Permutation: " << time_permute << endl;
		cout << "Prove permutation: " << time_prove_permute << endl;
		cout << "[[C]]+[[k]]: " << time_B << endl;
		cout << "Partial decryption: " << time_D1 << endl;
		cout << "Prove partial decryption: " << time_prove_D1 << endl;
		cout << "Total communication overhead: " << time_comm << endl << endl;

		cout << "Total elapsed time in us: " << time_total << endl;
		cout << "Percentage comparison / total server: " << (double) time_compare / time_total << endl;
		cout << "Percentage prove permutation / total server: " << (double)time_prove_permute / time_total << endl << endl;

		cout << "Total elapsed time in us for alpha: " << time_alpha << endl;

		cout << endl;

		io_service.stop();
		th.join();
	}
	catch (const logic_error& e) {
		cerr << e.what();
	}

	return 0;
}

int main(int argc, char* argv[]) {
	Server sv = Server();

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
