#include "party.hpp"

using namespace std;

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
  try {
    shared_ptr<KeySendableData> pk_sendable = ((ElGamalPublicKey*) pk_own.get())->generateSendableData();
    string pk_sendable_string = pk_sendable->toString();
    channel->writeWithSize(pk_sendable_string);
  } catch (const logic_error& e) {
			// Log error message in the exception object
			cerr << e.what();
	}

}

/*
*   Send asymmetric ciphertext to other party
*/
void Party::send_elgamal_msg(shared_ptr<AsymmetricCiphertext> c_m) {
  try {
    shared_ptr<AsymmetricCiphertextSendableData> c_m_sendable = ((ElGamalOnGroupElementCiphertext*) c_m.get())->generateSendableData();
    string c_m_sendable_string = c_m_sendable->toString();
    channel->writeWithSize(c_m_sendable_string);
  } catch (const logic_error& e) {
			// Log error message in the exception object
			cerr << e.what();
	}
}

/*
*   Send symmetric ciphertext to other party
*/
void Party::send_aes_msg(shared_ptr<SymmetricCiphertext> c_m) {

}

/*
*   Send encrypted vector to other party
*/
void Party::send_vec_enc(vector<shared_ptr<AsymmetricCiphertext>> vec_enc) {
  for(shared_ptr<AsymmetricCiphertext> elem : vec_enc) {
    send_elgamal_enc(elem);
  }
}

/*
*   Send encrypted template to other party
*/
void Party::send_template(shared_ptr<Template_enc> T_enc) {
  pair<int, int> size = T_enc->size();

  for(int i=0; i<size.first; i++) {
    for(int j=0; i<size.second; j++) {
      shared_ptr<AsymmetricCiphertext> elem = T_enc.get_elem(i, j);
      send_elgamal_enc(elem);
    }
  }
}

/*
*   Receive unencrypted message from other party
*/
string Party::recv_msg() {
  string msg;

  try {
    vector<byte> raw_msg;
    channel->readWithSizeIntoVector(raw_msg);
    const byte * uc = &(raw_msg[0]);
    msg = string(reinterpret_cast<char const*>(uc), raw_msg.size());
  } catch (const logic_error& e) {
			// Log error message in the exception object
			cerr << e.what();
	}


  return msg;
}

/*
*		Receive public key from connected party
*/
shared_ptr<PublicKey> Party::recv_pk() {
  shared_ptr<PublicKey> pk_sv;

  try {
    shared_ptr<KeySendableData> pk_sv_sendable = make_shared<ElGamalPublicKeySendableData>(dlog->getGenerator()->generateSendableData());
    vector<byte> raw_msg;
    channel->readWithSizeIntoVector(raw_msg);
    pk_sv_sendable->initFromByteVector(raw_msg);
    pk_sv = elgamal->reconstructPublicKey(pk_sv_sendable.get());

    shared_ptr<GroupElement> h = ((ElGamalPublicKey*) pk_sv.get())->getH();
    cout << "h: " << ((OpenSSLZpSafePrimeElement *)h.get())->getElementValue() << endl;
  } catch (const logic_error& e) {
			// Log error message in the exception object
			cerr << e.what();
	}

	return pk_sv;
}

/*
*   Receive asymmetric ciphertext from the other party
*/
shared_ptr<AsymmetricCiphertext> Party::recv_elgamal_msg() {
  shared_ptr<AsymmetricCiphertext> c_m;

  try {
    shared_ptr<AsymmetricCiphertextSendableData> c_m_sendable = make_shared<ElGamalOnGrElSendableData>(dlog->getGenerator()->generateSendableData(), dlog->getGenerator()->generateSendableData());
    vector<byte> raw_msg;
    channel->readWithSizeIntoVector(raw_msg);
    c_m_sendable->initFromByteVector(raw_msg);
    c_m = elgamal->reconstructCiphertext(c_m_sendable.get());
  } catch (const logic_error& e) {
			// Log error message in the exception object
			cerr << e.what();
	}

  return c_m;
}

/*
*   Receive symmetric ciphertext from the other party
*/
shared_ptr<SymmetricCiphertext> Party::recv_aes_msg() {
  shared_ptr<SymmetricCiphertext> result;

  return result;
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
  Template_enc T_enc;

  for(int i=0; i<template_size.first; i++) {
    for(int j=0; j<template_size.second; j++) {
      shared_ptr<AsymmetricCiphertext> s_enc = recv_elgamal_msg();

      T_enc.add_elem(s_enc, i);
    }
  }

  return make_shared<Template_enc>(T_enc);
}
