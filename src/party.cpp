#include "../include/party.hpp"

using namespace std;


/*
*		Convert an integer to byte array
*/
vector<unsigned char> Party::int_to_byte(int a) {
  vector<unsigned char> result(4);

  for(int i=0; i<4; i++) {
    result[i] = (a >> (8*(3-i)));
  }

  return result;
}

/*
*	 Convert a byte array to integer
*/
int Party::byte_to_int(vector<unsigned char> vec) {
  int result = 0;

  for(int i=0; i<vec.size(); i++) {
    result = (result << 8) + vec[i];
  }

  return result;
}

/*
*		Pad input with zeros (least significant bits) to match number of bits
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
*		Setup shared public key for double encryption
*/
void Party::key_setup(shared_ptr<PublicKey> pk_other) {
	shared_ptr<GroupElement> h_shared = dlog->exponentiate(((ElGamalPublicKey*) pk_other.get())->getH().get(), ((ElGamalPrivateKey*) sk_own.get())->getX());

	cout << "h_shared: " << ((OpenSSLZpSafePrimeElement *)h_shared.get())->getElementValue() << endl;

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
void Party::send_elgamal_msg(shared_ptr<AsymmetricCiphertext> c_m) {
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
*   Send encrypted vector to other party
*/
void Party::send_vec_enc(vector<shared_ptr<AsymmetricCiphertext>> vec_enc) {
  for(shared_ptr<AsymmetricCiphertext> elem : vec_enc) {
    send_elgamal_msg(elem);
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
      send_elgamal_msg(elem);
    }
  }
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
*		Receive public key from connected party
*/
shared_ptr<PublicKey> Party::recv_pk() {
  shared_ptr<PublicKey> pk_sv;

  shared_ptr<KeySendableData> pk_sv_sendable = make_shared<ElGamalPublicKeySendableData>(dlog->getGenerator()->generateSendableData());
  vector<byte> raw_msg;
  channel->readWithSizeIntoVector(raw_msg);
  pk_sv_sendable->initFromByteVector(raw_msg);
  pk_sv = elgamal->reconstructPublicKey(pk_sv_sendable.get());

  shared_ptr<GroupElement> h = ((ElGamalPublicKey*) pk_sv.get())->getH();
  cout << "h: " << ((OpenSSLZpSafePrimeElement *)h.get())->getElementValue() << endl;

	return pk_sv;
}

/*
*   Receive asymmetric ciphertext from the other party
*/
shared_ptr<AsymmetricCiphertext> Party::recv_elgamal_msg() {
  shared_ptr<AsymmetricCiphertext> c_m;

  shared_ptr<AsymmetricCiphertextSendableData> c_m_sendable = make_shared<ElGamalOnGrElSendableData>(dlog->getGenerator()->generateSendableData(), dlog->getGenerator()->generateSendableData());
  vector<byte> raw_msg;
  channel->readWithSizeIntoVector(raw_msg);
  c_m_sendable->initFromByteVector(raw_msg);
  c_m = elgamal->reconstructCiphertext(c_m_sendable.get());

  return c_m;
}


/*
*   Receive symmetric ciphertext from the other party
*/
shared_ptr<SymmetricCiphertext> Party::recv_aes_msg() {
  shared_ptr<IVCiphertext> c_m;

  vector<byte> raw_msg;
  cout << "before reading into vector" << endl;
	channel->readWithSizeIntoVector(raw_msg);
	cout << "before init from byte vector" << endl;
  c_m->initFromByteVector(raw_msg); 
  cout << "after init from byte vector" << endl;

  return c_m;
}

/*
*   Receive encrypted vector from the other party
*/
vector<shared_ptr<AsymmetricCiphertext>> Party::recv_vec_enc(int size) {
  vector<shared_ptr<AsymmetricCiphertext>> vec_enc;

  for(int i=0; i<size; i++) {
    shared_ptr<AsymmetricCiphertext> elem = recv_elgamal_msg();
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
      shared_ptr<AsymmetricCiphertext> s_enc = recv_elgamal_msg();

      //T_enc.add_elem(s_enc, i);
		T_enc.set_elem(s_enc, i, j);
    }
  }

  return make_shared<Template_enc>(T_enc);
}

biginteger Party::random_bit() {
	return getRandomInRange(0, 1, get_seeded_prg().get());
}

biginteger Party::random_bitstring(int bits) {
	return getRandomInRange(0, (biginteger) pow(2, bits), get_seeded_prg().get());
}

/*
*	Basic Coin Tossing protocol for party 1
*/
int Party::bct_p1() {
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
*	Basic Coin Tossing protocol for party 2
*/
int Party::bct_p2() {
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
*	Augmented Coin Tossing for party 1
*/
pair<biginteger, biginteger> Party::act_p1(int n, int l) {
	cout << "------------AUGMENTED COIN TOSSING FOR P1-----------" << endl;

	CmtPedersenWithProofsCommitter committer(channel, 40, dlog);

	//select r' = \sigma_1,...,\sigma_l \in (0,1) and s=s_1,...,s_l \in (0,1)^n
	biginteger r_acc = random_bitstring(l);
	cout << "r': " << r_acc << endl;
	biginteger s = random_bitstring(n * l);
	cout << "s: " << s << endl;

	//compute commitment over r' using randomness s and perform ZKPOK to prove knowledge of r'
	shared_ptr<CmtCommitValue> com_r_acc = make_shared<CmtBigIntegerCommitValue>(make_shared<biginteger>(r_acc));
	long id_r_acc = 0;
	cout << "committing on r' using randomness s..." << endl;
	committer.commit(com_r_acc, s, id_r_acc);
	committer.decommit(id_r_acc);

	cout << "proving knowledge on com(r',s)..." << endl;
	committer.proveKnowledge(id_r_acc);

	//p1 and p2 engage in BCT protocol l times to generate r_acc2
	biginteger r_acc2;

	for (int i = 0; i < l; i++) {
		int b = bct_p1();
		r_acc2 = r_acc2 + ((biginteger)b) * ((biginteger)pow(2, l - i - 1));
	}

	cout << "obtained r'' through BCT: " << r_acc2 << endl;

	//generate r = r' xor r''
	biginteger r = r_acc ^ r_acc2;

	cout << "compute r = r' xor r'': " << r << endl;

	//compute commitment over r and perform ZKPOK to prove knowledge of r
	shared_ptr<CmtCommitValue> com_r = make_shared<CmtBigIntegerCommitValue>(make_shared<biginteger>(r));
	long id_r = 1;
	cout << "committing on r..." << endl;
	committer.commit(com_r, id_r);
	committer.decommit(id_r);

	cout << "proving knowledge on com(r)..." << endl;
	committer.proveKnowledge(id_r);

	cout << "----------------------------------------------------" << endl;

	biginteger randomness = static_pointer_cast<BigIntegerRandomValue>(committer.getCommitmentPhaseValues(id_r)->getR())->getR();

	return make_pair(r, randomness);
}

/*
*	Augmented Coin Tossing for party 2
*/
shared_ptr<CmtRCommitPhaseOutput> Party::act_p2(int n, int l) {
	cout << "------------AUGMENTED COIN TOSSING FOR P2-----------" << endl;

	CmtPedersenWithProofsReceiver receiver(channel, 40, dlog);

	//receive commitment over r' from p1
	auto com_r_acc = receiver.receiveCommitment();
	long id_r_acc = 0;
	auto result_r_acc = receiver.receiveDecommitment(id_r_acc);
	if (result_r_acc == NULL) {
		cout << "commitment of r' using randomness s failed" << endl;
	}
	else {
		cout << "succesfully obtained commitment over r' using randomness s" << endl;
		cout << "r': " << result_r_acc->toString() << endl;
	}

	//verify zkpof-proof over commitment of r
	cout << "ZKPOF-proof on com(r',s) accepted: " << receiver.verifyKnowledge(id_r_acc) << endl;

	//p1 and p2 engage in BCT protocol l times to generate r_acc2
	biginteger r_acc2;

	for (int i = 0; i < l; i++) {
		int b = bct_p2();
		r_acc2 = r_acc2 + ((biginteger)b) * ((biginteger)pow(2, l - i - 1));
	}

	cout << "obtained r'' through BCT: " << r_acc2 << endl;

	//receive commitment over r from p1
	auto com_r = receiver.receiveCommitment();
	long id_r = 1;
	auto result_r = receiver.receiveDecommitment(id_r);
	if (result_r == NULL) {
		cout << "commitment failed" << endl;
	}
	else {
		cout << "succesfully obtained commitment over r" << endl;
		cout << "r: " << result_r->toString() << endl;
	}

	cout << "ZKPOF-proof on com(r) accepted: " << receiver.verifyKnowledge(id_r) << endl;

	cout << "----------------------------------------------------" << endl;

	return com_r;
}

/*
*	Input Commitment protocol for party 1
*/
biginteger Party::ic_p1(biginteger x) {
	cout << "------------INPUT COMMITMENT FOR P1-----------------" << endl;

	cout << "entering protocol with input x: " << x << endl;

	CmtPedersenWithProofsCommitter committer(channel, 40, dlog);

	//compute commitment over x and perform ZKPOF on com(x,r')
	shared_ptr<CmtCommitValue> com_x = make_shared<CmtBigIntegerCommitValue>(make_shared<biginteger>(x));
	cout << "number of bits:" << NumberOfBits(x) << endl;
	int n = NumberOfBits(x);
	biginteger r_acc = random_bitstring(pow(2, n));
	long id_x_r_acc = 0;
	cout << "committing on x using randomness r'..." << endl;
	committer.commit(com_x, r_acc, id_x_r_acc);
	committer.decommit(id_x_r_acc);

	cout << "proving knowledge on com(x,r')..." << endl;
	committer.proveKnowledge(id_x_r_acc);

	//perform augmented coin tossing protocol to obtain output (r, r'')
	pair<biginteger, biginteger> r_r_acc2 = act_p1(pow(2,n), n);
	biginteger r = r_r_acc2.first;
	biginteger r_acc2 = r_r_acc2.second;

	//compute com(x,r) and perform ZKPOF on com(x,r)
	cout << "committing on x using randomness r..." << endl;
	long id_x_r = 1;
	committer.commit(com_x, r, id_x_r);
	committer.decommit(id_x_r);

	cout << "proving knowledge on com(x,r)..." << endl;
	committer.proveKnowledge(id_x_r);

	cout << "----------------------------------------------------" << endl;

	return r;
}

/*
*	Input Commitment protocol for party 2
*/
shared_ptr<CmtRCommitPhaseOutput> Party::ic_p2() {
	cout << "------------INPUT COMMITMENT FOR P2-----------------" << endl;

	CmtPedersenWithProofsReceiver receiver(channel, 40, dlog);

	//receive commitment over x from p1
	auto com_x_r_acc = receiver.receiveCommitment();
	long id_x_r_acc = 0;
	auto result_x_r_acc = receiver.receiveDecommitment(id_x_r_acc);
	if (result_x_r_acc == NULL) {
		cout << "commitment of x using randomness r' failed" << endl;
	}
	else {
		cout << "succesfully obtained commitment over x using randomness r'" << endl;
		cout << "x: " << result_x_r_acc->toString() << endl;
	}

	//verify ZKPOF over com(x,r')
	cout << "ZKPOF on com(x,r') accepted: " << receiver.verifyKnowledge(id_x_r_acc) << endl;

	//perform augmented coin tossing protocol to obtain output c'' = com(r, r'')
	int n = NumberOfBits(*((biginteger*) result_x_r_acc->getX().get()));
	auto com_r_r_acc = act_p2(pow(2, n), n);

	//receive commitment over x using randomness r
	auto com_x_r = receiver.receiveCommitment();
	long id_x_r = 1;
	auto result_x_r = receiver.receiveDecommitment(id_x_r);
	if (result_x_r == NULL) {
		cout << "commitment of x using randomness r failed" << endl;
	}
	else {
		cout << "succesfully obtained commitment over x using randomness r" << endl;
		cout << "x: " << result_x_r->toString() << endl;
	}

	//verify ZKPOF over com(x,r)
	cout << "ZKPOF on com(x,r) accepted: " << receiver.verifyKnowledge(id_x_r) << endl;

	cout << "----------------------------------------------------" << endl;
}
