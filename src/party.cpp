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
  auto dlog2 = make_shared<OpenSSLDlogECF2m>();

  shared_ptr<CmtCommitter> committer = make_shared<CmtPedersenCommitter>(channel, dlog2);

  shared_ptr<CmtReceiver> receiver = make_shared<CmtPedersenReceiver>(channel, dlog2);

  biginteger b = random_bit();
  auto r1_com = make_shared<CmtBigIntegerCommitValue>(make_shared<biginteger>(b));
  //auto r1_com = committer->sampleRandomCommitValue();
  cout << "the committed value is:" << r1_com->toString() << endl;

  auto commitment = receiver->receiveCommitment();

  committer->commit(r1_com, 0);

  auto result = receiver->receiveDecommitment(1);

  committer->decommit(0);

  if (result == NULL) {
    cout << "commitment failed" << endl;
  } else {
    cout << "the committed value is:" << result->toString() << endl;
  }

  //biginteger r2 = *((biginteger *)result->getX().get());
  //biginteger r1 = *((biginteger *)r1_com->getX().get());
  int r2 = stoi(result->toString());
  int r1 = stoi(r1_com->toString());
  int r = (r1^r2);
  cout << "r: " << r << endl;

  return r;
}

/*
*	Basic Coin Tossing protocol for party 2
*/
int Party::bct_p2() {
  auto dlog2 = make_shared<OpenSSLDlogECF2m>();
  shared_ptr<CmtReceiver> receiver = make_shared<CmtPedersenReceiver>(channel, dlog2);
  shared_ptr<CmtCommitter> committer = make_shared<CmtPedersenCommitter>(channel, dlog2);

  biginteger b = random_bit();
  auto r2_com = make_shared<CmtBigIntegerCommitValue>(make_shared<biginteger>(b));
  //auto r2_com = committer->sampleRandomCommitValue();
  cout << "the committed value is:" << r2_com->toString() << endl;
  committer->commit(r2_com, 1);

  auto commitment = receiver->receiveCommitment();

  committer->decommit(1);

  auto result = receiver->receiveDecommitment(0);
  if (result == NULL) {
    cout << "commitment failed" << endl;
  } else {
    cout << "the committed value is:" << result->toString() << endl;
  }

  //biginteger r1 = *((biginteger *)result->getX().get());
  int r1 = stoi(result->toString());
  //biginteger r2 = *((biginteger *)r2_com->getX().get());
  int r2 = stoi(r2_com->toString());
  int r = (r1^r2);
  cout << "r: " << r << endl;

  return r;
}

/*
*
*/

void Party::act_p1(int n, int l) {
	auto dlog2 = make_shared<OpenSSLDlogECF2m>();
	shared_ptr<CmtCommitter> committer = make_shared<CmtPedersenCommitter>(channel, dlog2);

	//first sample random number of n bits long, obtaining string r'
	biginteger r_acc = random_bitstring(n);
	auto r_acc_comm = make_shared<CmtBigIntegerCommitValue>(make_shared<biginteger>(r_acc));

	cout << "r': " << r_acc << endl;

	//also try to sample random number of n*l bits long, obtaining string s_inv

	//make commitment over first random number with second random number as randomness
	committer->commit(r_acc_comm, 0);

	//zero knowledge strong proof of knowledge over the commitment with p2
	//basic coin tossing protocol is executed l times, obtaining string r''

	biginteger r_acc2;

	for (int i = 0; i < l; i++) {
		int b = bct_p1();
		cout << "b: " << b << endl;
		r_acc2 = r_acc2 + ((biginteger) b)* ((biginteger) pow(2, l - i - 1));
	}

	cout << "r_'': " << r_acc2 << endl;

	//compute r = r' xor r'' 

	biginteger r = r_acc ^ r_acc2;

	cout << "r: " << r << endl;
	//compute commitment over r ??? and proof zk over commitment
}

void Party::act_p2(int n, int l) {
	auto dlog2 = make_shared<OpenSSLDlogECF2m>();
	shared_ptr<CmtReceiver> receiver = make_shared<CmtPedersenReceiver>(channel, dlog2);

	auto commitment = receiver->receiveCommitment();

	for (int i = 0; i < l; i++) {
		int b = bct_p2();
		cout << "b: " << b << endl;
	}
}
