/*
*	Created using libscapi (see https://crypto.biu.ac.il/SCAPI/)
*	Authors: Ruth Scholten
*/

#include "../include/party.hpp"

using namespace std;

/*
*	Pad input with zeros (least significant bits) to match number of bits
*/
void Party::pad(vector<unsigned char> &input, int bits) {
	int i = bits-input.size()*8;
	if(i > 0) {
		for(int j = 0; j<i; j+=8) {
			vector<unsigned char> byte_zeros = int_to_byte(0);
			input.push_back(byte_zeros[0]);
		}
	}
}

/*
*	Setup shared public key for threshold encryption
*/
void Party::key_setup(shared_ptr<PublicKey> pk_other) {
	shared_ptr<GroupElement> h_shared = dlog->exponentiate(((ElGamalPublicKey*) pk_other.get())->getH().get(), ((ElGamalPrivateKey*) sk_own.get())->getX());

	pk_shared = make_shared<ElGamalPublicKey>(ElGamalPublicKey(h_shared));

	elgamal->setKey(pk_shared);
}

/*
*   Send unencrypted message to other party
*/
void Party::send_msg(string msg) {
	channel->writeWithSize(msg);
}

void Party::send_msg(int msg) {
	string msg_string = to_string(msg);
	send_msg(msg_string);
}

void Party::send_biginteger(biginteger msg) {
	size_t size = bytesCount(msg);
	byte msg_byte[size];
	encodeBigInteger(msg, msg_byte, size);
	channel->writeWithSize(msg_byte, size);
}

/*
*	Send group element to other party
*/
void Party::send_group_element(shared_ptr<GroupElement> elem) {
	auto elem_sendable = elem->generateSendableData();
	string elem_sendable_string = elem_sendable->toString();
	channel->writeWithSize(elem_sendable_string);
}

/*
*   Send public key to other party
*/
void Party::send_pk() {
  shared_ptr<KeySendableData> pk_sendable = ((ElGamalPublicKey*) pk_own.get())->generateSendableData();
  string pk_sendable_string = pk_sendable->toString();
  channel->writeWithSize(pk_sendable_string);
}

/*
*   Send asymmetric ciphertext to other party
*/
void Party::send_msg_enc(shared_ptr<AsymmetricCiphertext> c_m) {
  shared_ptr<AsymmetricCiphertextSendableData> c_m_sendable = ((ElGamalOnGroupElementCiphertext*) c_m.get())->generateSendableData();
  string c_m_sendable_string = c_m_sendable->toString();
  channel->writeWithSize(c_m_sendable_string);
}

/*
*   Send symmetric ciphertext to other party
*/
void Party::send_aes_msg(shared_ptr<SymmetricCiphertext> c_m) {
	string c_m_string = c_m->toString();
	channel->writeWithSize(c_m_string);
}

/*
*	Send vector of bigintegers to other party
*/
void Party::send_vec_biginteger(vector<biginteger> vec_biginteger) {
	//first send size of vector to the other party
	send_msg(vec_biginteger.size());

	for (biginteger elem : vec_biginteger) {
		send_biginteger(elem);
	}
}

/*
*   Send vector of group elements to other party
*/
void Party::send_vec_group_element(vector<shared_ptr<GroupElement>> vec_group_element) {
	//first send size of vector to the other party
	send_msg(vec_group_element.size());

	for (shared_ptr<GroupElement> elem : vec_group_element) {
		send_group_element(elem);
	}
}

/*
*   Send encrypted vector to other party
*/
void Party::send_vec_enc(vector<shared_ptr<AsymmetricCiphertext>> vec_enc) {
	//first send size of vector to the other party
	send_msg(vec_enc.size());

	for(shared_ptr<AsymmetricCiphertext> elem : vec_enc) {
		send_msg_enc(elem);
	}
}

/*
*   Send encrypted template to other party
*/
void Party::send_template(shared_ptr<Template_enc> T_enc) {
  pair<int, int> size = T_enc->size();

  for(int i=0; i<size.first; i++) {
    for(int j=0; j<size.second; j++) {
      shared_ptr<AsymmetricCiphertext> elem = T_enc->get_elem(i, j);
      send_msg_enc(elem);
    }
  }
}

/*
*	Send signature to other party
*/
void Party::send_signature(Signature sig) {
	send_biginteger(sig.s);
	send_biginteger(sig.c);
}

/*
*   Receive unencrypted message from other party
*/
string Party::recv_msg() {
	string msg;

	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);
	const byte * uc = &(raw_msg[0]);
	msg = string(reinterpret_cast<char const*>(uc), raw_msg.size());

	return msg;
}

/*
*	Receive biginteger from other party
*/
biginteger Party::recv_biginteger() {
	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);
	const byte* uc = &(raw_msg[0]);
	
	return decodeBigInteger(uc, raw_msg.size());
}

/*
*	Receive group element from other party
*/
shared_ptr<GroupElement> Party::recv_group_element() {
	shared_ptr<GroupElement> elem;

	shared_ptr<GroupElementSendableData> elem_sendable = make_shared<ECElementSendableData>(dlog->getOrder(), dlog->getOrder());
	//shared_ptr<GroupElementSendableData> elem_sendable = make_shared<ZpElementSendableData>(dlog->getOrder());
	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);
	elem_sendable->initFromByteVector(raw_msg);
	elem = dlog->reconstructElement(true, elem_sendable.get());

	return elem;
}

/*
*	Receive public key from other party
*/
shared_ptr<PublicKey> Party::recv_pk() {
	shared_ptr<PublicKey> pk_sv;

	shared_ptr<KeySendableData> pk_sv_sendable = make_shared<ElGamalPublicKeySendableData>(dlog->getGenerator()->generateSendableData());
	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);
	pk_sv_sendable->initFromByteVector(raw_msg);
	pk_sv = elgamal->reconstructPublicKey(pk_sv_sendable.get());

	return pk_sv;
}

/*
*   Receive asymmetric ciphertext from the other party
*/
shared_ptr<AsymmetricCiphertext> Party::recv_msg_enc() {
  shared_ptr<AsymmetricCiphertext> c_m;

  shared_ptr<AsymmetricCiphertextSendableData> c_m_sendable = make_shared<ElGamalOnGrElSendableData>(dlog->getGenerator()->generateSendableData(), dlog->getGenerator()->generateSendableData());
  vector<byte> raw_msg;
  channel->readWithSizeIntoVector(raw_msg);
  c_m_sendable->initFromByteVector(raw_msg);
  c_m = elgamal->reconstructCiphertext(c_m_sendable.get());

  return c_m;
}


/*
*   Receive symmetric ciphertext (AES encryption) from the other party
*/
shared_ptr<SymmetricCiphertext> Party::recv_aes_msg() {
  vector<byte> empty;
  shared_ptr<SymmetricCiphertext> c_m = make_shared<IVCiphertext>(make_shared<ByteArraySymCiphertext>(empty), empty);

  vector<byte> raw_msg;
  channel->readWithSizeIntoVector(raw_msg);

  const byte* uc = &(raw_msg[0]);
  string msg = string(reinterpret_cast<char const*>(uc), raw_msg.size());
  c_m->initFromString(msg);

  return c_m;
}

/*
*	Receive vector of bigintegers from the other party
*/
vector<biginteger> Party::recv_vec_biginteger() {
	vector<biginteger> vec_biginteger;

	//first fetch size of vector sent by the other party
	int size = stoi(recv_msg());

	for (int i = 0; i < size; i++) {
		biginteger elem = recv_biginteger();
		vec_biginteger.push_back(elem);
	}

	return vec_biginteger;
}

/*
*	Receive vector of group elements from the other party
*/
vector<shared_ptr<GroupElement>> Party::recv_vec_group_element() {
	vector<shared_ptr<GroupElement>> vec_group_element;

	//first fetch size of vector sent by the other party
	int size = stoi(recv_msg());

	for (int i = 0; i < size; i++) {
		shared_ptr<GroupElement> elem = recv_group_element();
		vec_group_element.push_back(elem);
	}

	return vec_group_element;
}

/*
*   Receive encrypted vector (asymmetric ciphertext) from the other party
*/
vector<shared_ptr<AsymmetricCiphertext>> Party::recv_vec_enc() {
  vector<shared_ptr<AsymmetricCiphertext>> vec_enc;

  //first fetch size of vector sent by the other party
  int size = stoi(recv_msg());

  for(int i=0; i<size; i++) {
    shared_ptr<AsymmetricCiphertext> elem = recv_msg_enc();
    vec_enc.push_back(elem);
  }

  return vec_enc;
}

/*
*   Receive and reconstruct template obtained via a communication channel from the other party
*/
shared_ptr<Template_enc> Party::recv_template() {
  Template_enc T_enc(template_size);

  for(int i=0; i<template_size.first; i++) {
    for(int j=0; j<template_size.second; j++) {
      shared_ptr<AsymmetricCiphertext> s_enc = recv_msg_enc();

      //T_enc.add_elem(s_enc, i);
		T_enc.set_elem(s_enc, i, j);
    }
  }

  return make_shared<Template_enc>(T_enc);
}

/*
*	Receive signature from other party
*/
Signature Party::recv_signature() {
	biginteger s = recv_biginteger();
	biginteger c = recv_biginteger();

	Signature sig = { s,c };
	return sig;
}

/*
*	Generate random bit
*/
biginteger Party::random_bit() {
	return getRandomInRange(0, 1, get_seeded_prg().get());
}

/*
*	Abort the protocol
*/
void Party::check_abort(bool verification) {
	if (!verification) {
		exit(1);
	}
}

/*
*	Generate random bit string of n bits long that does not exceed q
*/
biginteger Party::random_bitstring(int bits) {
	biginteger q = dlog->getOrder();
	biginteger result = getRandomInRange(0, q - 1, get_seeded_prg().get());

	if (bits > 0 && bits < NumberOfBits(q)) {
		result = getRandomInRange(0, ((biginteger) pow(2, bits))-1, get_seeded_prg().get());
	}

	return result;
}

/*
*	Compute m = (u, [[T_u]])
*/
vector<byte> Party::compute_m(int u, shared_ptr<Template_enc> T_enc) {
	vector<byte> m(int_to_byte(u));

	pair<int, int> size = T_enc->size();

	for (int i = 0; i < size.first; i++) {
		for (int j = 0; j < size.second; j++) {
			vector<byte> c1 = dlog->decodeGroupElementToByteArray(((ElGamalOnGroupElementCiphertext*)T_enc->get_elem(i, j).get())->getC1().get());
			vector<byte> c2 = dlog->decodeGroupElementToByteArray(((ElGamalOnGroupElementCiphertext*)T_enc->get_elem(i, j).get())->getC2().get());

			m.insert(m.end(), c1.begin(), c1.end());
			m.insert(m.end(), c2.begin(), c2.end());
		}
	}

	return m;
}

/*
*	Compute n = (u, [[k]], AES_k(1))
*/
vector<byte> Party::compute_n(int u, shared_ptr<AsymmetricCiphertext> k_enc, shared_ptr<SymmetricCiphertext> aes_k) {
	vector<byte> n(int_to_byte(u));

	vector<byte> c1 = dlog->decodeGroupElementToByteArray(((ElGamalOnGroupElementCiphertext*)k_enc.get())->getC1().get());
	vector<byte> c2 = dlog->decodeGroupElementToByteArray(((ElGamalOnGroupElementCiphertext*)k_enc.get())->getC2().get());

	n.insert(n.end(), c1.begin(), c1.end());
	n.insert(n.end(), c2.begin(), c2.end());

	string aes_k_string = aes_k->toString();
	vector<byte> aes_k_byte(aes_k_string.begin(), aes_k_string.end());

	n.insert(n.end(), aes_k_byte.begin(), aes_k_byte.end());

	return n;
}

/*
*	Sigma protocol proof
*	Equality of exponents proof of Step 26
*/
void Party::zkpk_prove(biginteger x, vector<shared_ptr<GroupElement>> y, vector<shared_ptr<GroupElement>> bases) {
	biginteger q = dlog->getOrder();

	//Choose r \in_R Z_q
	biginteger r = getRandomInRange(0, q - 1, get_seeded_prg().get());

	vector<shared_ptr<GroupElement>> t;

	//Compute t1 = g^r, t2 = h^r, t3 = ..., etc
	for (int i = 0; i < bases.size(); i++) {
		t.push_back(dlog->exponentiate(bases[i].get(), r));
	}

	//Send t1, t2, etc to verifier
	send_vec_group_element(t);

	//Receive challenge from verifier
	biginteger c = recv_biginteger();

	//Compute response
	biginteger s = mod(r - c * x, q);

	//Send response to verifier
	send_biginteger(s);
}

/*
*	Sigma protocol verification
*	Equality of exponents proof of Step 26
*/
bool Party::zkpk_verify(int k, vector<shared_ptr<GroupElement>> y, vector<shared_ptr<GroupElement>> bases) {
	bool result = true;

	//Receive t1, t2, ... from prover
	vector<shared_ptr<GroupElement>> t = recv_vec_group_element();

	//Choose challenge c \in_R {0,1}^k
	biginteger c = random_bitstring(k);

	//Send challenge to prover
	send_biginteger(c);

	//Receive response from prover
	auto start = std::chrono::high_resolution_clock::now();
	biginteger s = recv_biginteger();

	//Verify

	for (int i = 0; i < bases.size(); i++) {
		auto left = dlog->multiplyGroupElements(dlog->exponentiate(bases[i].get(), s).get(), dlog->exponentiate(y[i].get(), c).get());
		result = (result && (*left.get() == *t[i].get()));
	}

	auto end = std::chrono::high_resolution_clock::now();

	cout << "Time zkpk_verify: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << endl;

	return result;
}

/*
*	Sigma protocol proof
*	Equality of exponents proof of Step 16-18 in partially key release protocol
*/
void Party::zkpk_prove_with_com(pair<biginteger, biginteger> x, vector<shared_ptr<GroupElement>> y, vector<shared_ptr<GroupElement>> bases) {
	biginteger q = dlog->getOrder();

	//Choose k1, k2 \in_R Z_q
	biginteger k1 = getRandomInRange(0, q - 1, get_seeded_prg().get());
	biginteger k2 = getRandomInRange(0, q - 1, get_seeded_prg().get());

	vector<shared_ptr<GroupElement>> t;

	//Compute t1 = g^k1, t2 = h^k1, t3 = g^k2 h^k1
	t.push_back(dlog->exponentiate(bases[0].get(), k1));
	t.push_back(dlog->exponentiate(bases[1].get(), k1));
	t.push_back(dlog->multiplyGroupElements(dlog->exponentiate(bases[2].get(), k2).get(), dlog->exponentiate(bases[3].get(), k1).get()));

	//Send t1, t2, t3 to verifier
	send_vec_group_element(t);

	//Receive challenge from verifier
	biginteger c = recv_biginteger();

	//Compute response
	vector<biginteger> s;
	s.push_back(mod(k1 - c * x.first, q));
	s.push_back(mod(k2 - c * x.second, q));

	//Send response to verifier
	send_vec_biginteger(s);
}

/*
*	Sigma protocol verification
*	Equality of exponents proof of Step 16-18 in partially malicious key release protocol
*/
bool Party::zkpk_verify_with_com(int m, vector<shared_ptr<GroupElement>> y, vector<shared_ptr<GroupElement>> bases) {
	//Receive t1, t2, t3 from prover
	vector<shared_ptr<GroupElement>> t = recv_vec_group_element();

	//Choose challenge c \in_R {0,1}^m
	biginteger c = mod(random_bitstring(m), dlog->getOrder());

	//Send challenge to prover
	send_biginteger(c);

	//Receive response from prover
	vector<biginteger> s = recv_vec_biginteger();

	//Verify
	auto left0 = dlog->multiplyGroupElements(dlog->exponentiate(bases[0].get(), s[0]).get(), dlog->exponentiate(y[0].get(), c).get());
	auto left1 = dlog->multiplyGroupElements(dlog->exponentiate(bases[1].get(), s[0]).get(), dlog->exponentiate(y[1].get(), c).get());
	auto left2 = dlog->multiplyGroupElements(dlog->multiplyGroupElements(dlog->exponentiate(bases[2].get(), s[1]).get(), dlog->exponentiate(bases[3].get(), s[0]).get()).get(), dlog->exponentiate(y[2].get(), c).get());

	return (*left0.get() == *t[0].get()) && (*left1.get() == *t[1].get()) && (*left2.get() == *t[2].get());
}

/*
*	Basic Coin Tossing protocol for party 1 (1-bit version)
*/
int Party::bct_bit_p1() {
  shared_ptr<CmtCommitter> committer = make_shared<CmtPedersenCommitter>(channel, dlog);

  shared_ptr<CmtReceiver> receiver = make_shared<CmtPedersenReceiver>(channel, dlog);

  biginteger b = random_bit();
  auto r1_com = make_shared<CmtBigIntegerCommitValue>(make_shared<biginteger>(b));
  //auto r1_com = committer->sampleRandomCommitValue();
  //cout << "the committed value is:" << r1_com->toString() << endl;

  auto commitment = receiver->receiveCommitment();

  committer->commit(r1_com, 0);

  auto result = receiver->receiveDecommitment(1);

  committer->decommit(0);

  if (result == NULL) {
    cout << "commitment in basic coin tossing protocol failed" << endl;
  } else {
    //cout << "the committed value is:" << result->toString() << endl;
  }

  //biginteger r2 = *((biginteger *)result->getX().get());
  //biginteger r1 = *((biginteger *)r1_com->getX().get());
  int r2 = stoi(result->toString());
  int r1 = stoi(r1_com->toString());
  int r = (r1^r2);
  //cout << "r: " << r << endl;

  return r;
}

/*
*	Basic Coin Tossing protocol for party 1
*/
biginteger Party::bct_p1() {
	shared_ptr<CmtCommitter> committer = make_shared<CmtPedersenCommitter>(channel, dlog);

	shared_ptr<CmtReceiver> receiver = make_shared<CmtPedersenReceiver>(channel, dlog);

	biginteger b = getRandomInRange(0, dlog->getOrder()-1, get_seeded_prg().get());

	auto r1_com = make_shared<CmtBigIntegerCommitValue>(make_shared<biginteger>(b));
	//auto r1_com = committer->sampleRandomCommitValue();
	//cout << "the committed value is:" << r1_com->toString() << endl;

	auto commitment = receiver->receiveCommitment();

	committer->commit(r1_com, 0);

	auto result = receiver->receiveDecommitment(1);

	committer->decommit(0);

	if (result == NULL) {
		cout << "commitment in basic coin tossing protocol failed" << endl;
	}
	else {
		//cout << "the committed value is:" << result->toString() << endl;
	}

	biginteger r2 = *((biginteger *)result->getX().get());
	biginteger r1 = *((biginteger *)r1_com->getX().get());
	//int r2 = stoi(result->toString());
	//int r1 = stoi(r1_com->toString());
	biginteger r = (r1 ^ r2);
	//cout << "r: " << r << endl;

	return r;
}

/*
*	Basic Coin Tossing protocol for party 2 (one-bit version)
*/
int Party::bct_bit_p2() {
  shared_ptr<CmtReceiver> receiver = make_shared<CmtPedersenReceiver>(channel, dlog);
  shared_ptr<CmtCommitter> committer = make_shared<CmtPedersenCommitter>(channel, dlog);

  biginteger b = random_bit();
  auto r2_com = make_shared<CmtBigIntegerCommitValue>(make_shared<biginteger>(b));
  //auto r2_com = committer->sampleRandomCommitValue();
  //cout << "the committed value is:" << r2_com->toString() << endl;
  committer->commit(r2_com, 1);

  auto commitment = receiver->receiveCommitment();

  committer->decommit(1);

  auto result = receiver->receiveDecommitment(0);
  if (result == NULL) {
    cout << "commitment in basic coin tossing protocol failed" << endl;
  } else {
    //cout << "the committed value is:" << result->toString() << endl;
  }

  //biginteger r1 = *((biginteger *)result->getX().get());
  int r1 = stoi(result->toString());
  //biginteger r2 = *((biginteger *)r2_com->getX().get());
  int r2 = stoi(r2_com->toString());
  int r = (r1^r2);
  //cout << "r: " << r << endl;

  return r;
}

/*
*	Basic Coin Tossing protocol for party 2
*/
biginteger Party::bct_p2() {
	shared_ptr<CmtReceiver> receiver = make_shared<CmtPedersenReceiver>(channel, dlog);
	shared_ptr<CmtCommitter> committer = make_shared<CmtPedersenCommitter>(channel, dlog);

	biginteger b = getRandomInRange(0, dlog->getOrder()-1, get_seeded_prg().get());
	auto r2_com = make_shared<CmtBigIntegerCommitValue>(make_shared<biginteger>(b));
	//auto r2_com = committer->sampleRandomCommitValue();
	//cout << "the committed value is:" << r2_com->toString() << endl;
	committer->commit(r2_com, 1);

	auto commitment = receiver->receiveCommitment();

	committer->decommit(1);

	auto result = receiver->receiveDecommitment(0);
	if (result == NULL) {
		cout << "commitment in basic coin tossing protocol failed" << endl;
	}
	else {
		//cout << "the committed value is:" << result->toString() << endl;
	}

	biginteger r1 = *((biginteger *)result->getX().get());
	//int r1 = stoi(result->toString());
	biginteger r2 = *((biginteger *)r2_com->getX().get());
	//int r2 = stoi(r2_com->toString());
	biginteger r = (r1 ^ r2);
	//cout << "r: " << r << endl;

	return r;
}

/*
*	Authenticated Computation protocol for party 1
*/
void Party::ac_p1(shared_ptr<CmtWithProofsCommitter> committer, biginteger x, biginteger r, long id_x_r, string x_name, string r_name) {
	//compute commitment over x using randomness r and perform ZKPOK to prove knowledge of x
	shared_ptr<CmtCommitValue> com_x = make_shared<CmtBigIntegerCommitValue>(make_shared<biginteger>(x));
	//cout << "committing on " << x_name << " using random-tape " << r_name << "..." << endl;
	committer->commit(com_x, r, id_x_r);

	//prove knowledge on com(x,r)
	//cout << "proving knowledge on com(" << x_name << "," << r_name << ")..." << endl;
	committer->proveKnowledge(id_x_r);
}

void Party::ac_p1(shared_ptr<CmtWithProofsCommitter> committer, biginteger x, long id_x_r, string x_name) {
	biginteger r = getRandomInRange(0, dlog->getOrder()-1, get_seeded_prg().get());

	ac_p1(committer, x, r, id_x_r, x_name, "-random-");
}

/*
*	Authenticated Computation protocol for party 2
*/
shared_ptr<CmtCCommitmentMsg> Party::ac_p2(shared_ptr<CmtWithProofsReceiver> receiver, long id_x_r, string x_name, string r_name) {
	//receive commitment over r' from p1
	auto com_x = receiver->receiveCommitment();

	//verify zkpof over commitment of r
	bool verified = receiver->verifyKnowledge(id_x_r);
	//cout << "ZKPOF on com(" << x_name << "," << r_name << ") accepted: " << verified << endl;

	shared_ptr<CmtPedersenCommitmentMessage> com_x_pedersen = static_pointer_cast<CmtPedersenCommitmentMessage>(receiver->CmtReceiver::getCommitmentPhaseValues(com_x->getCommitmentId()));

	return com_x_pedersen;
}

shared_ptr<CmtCCommitmentMsg> Party::ac_p2(shared_ptr<CmtWithProofsReceiver> receiver, long id_x_r, string x_name) {
	return ac_p2(receiver, id_x_r, x_name, "-random-");
}

/*
*	Augmented Coin Tossing for party 1
*/
tuple<biginteger, biginteger, shared_ptr<GroupElement>> Party::act_p1(shared_ptr<CmtWithProofsCommitter> committer, int n, int l) {
	//cout << "------------AUGMENTED COIN TOSSING FOR P1-----------" << endl;

	biginteger q = dlog->getOrder();

	//select r' = \sigma_1,...,\sigma_l \in (0,1) and s=s_1,...,s_l \in (0,1)^n
	//biginteger r_acc = mod(random_bitstring(l), q);
	biginteger r_acc = getRandomInRange(0, q - 1, get_seeded_prg().get());
	//cout << "r': " << r_acc << endl;
	
	//biginteger s = mod(random_bitstring(n*l), q);
	biginteger s = getRandomInRange(0, q - 1, get_seeded_prg().get());
	//cout << "s: " << s << endl;

	long id_r_acc_s = 0;

	//engage in Authenticated Computation protocol with p2
	ac_p1(committer, r_acc, s, id_r_acc_s, "r'", "s");

	//p1 and p2 engage in BCT protocol l times to generate r_acc2
	biginteger r_acc2;

	for (int i = 0; i < l; i++) {
		biginteger b = bct_bit_p1();
		r_acc2 = r_acc2 + ((biginteger)b) * ((biginteger)pow(2, l - i - 1));
	}

	//cout << "obtained r'' through BCT: " << r_acc2 << endl;

	//generate r = r' xor r''
	biginteger r = r_acc ^ r_acc2;

	//cout << "compute r = r' xor r'': " << r << endl;

	//compute commitment over r and send to p2 using authenticated computation protocol
	long id_r = 1;
	ac_p1(committer, r, id_r, "r");

	//cout << "----------------------------------------------------" << endl;

	biginteger randomtape = static_pointer_cast<BigIntegerRandomValue>(committer->getCommitmentPhaseValues(id_r)->getR())->getR();

	auto com_r_pedersen = static_pointer_cast<GroupElement>(committer->getCommitmentPhaseValues(id_r)->getComputedCommitment());

	return make_tuple(r, randomtape, com_r_pedersen);
}

/*
*	Augmented Coin Tossing for party 2
*/
shared_ptr<CmtCCommitmentMsg> Party::act_p2(shared_ptr<CmtWithProofsReceiver> receiver, int n, int l) {
	//cout << "------------AUGMENTED COIN TOSSING FOR P2-----------" << endl;

	long id_r_acc_s = 0;
	shared_ptr<CmtCCommitmentMsg> com_r_acc_s = ac_p2(receiver, id_r_acc_s, "r'", "s");

	//p1 and p2 engage in BCT protocol l times to generate r_acc2
	biginteger r_acc2;

	for (int i = 0; i < l; i++) {
		biginteger b = bct_bit_p2();
		r_acc2 = r_acc2 + ((biginteger)b) * ((biginteger)pow(2, l - i - 1));
	}

	//cout << "obtained r'' through BCT: " << r_acc2 << endl;

	//receive commitment over r from p1 and verify knowledge
	long id_r = 1;
	shared_ptr<CmtCCommitmentMsg> com_r = ac_p2(receiver, id_r, "r");

	//cout << "----------------------------------------------------" << endl;

	return com_r;
}
