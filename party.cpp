#include "party.hpp"

using namespace std;

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
*		Setup shared public key for double encryption
*/
void Party::key_setup(shared_ptr<PublicKey> pk_other) {
	shared_ptr<GroupElement> h_shared = dlog->exponentiate(((ElGamalPublicKey*) pk_other.get())->getH().get(), ((ElGamalPrivateKey*) sk_own.get())->getX());

	cout << "h_shared: " << ((OpenSSLZpSafePrimeElement *)h_shared.get())->getElementValue() << endl;

	pk_shared = make_shared<ElGamalPublicKey>(ElGamalPublicKey(h_shared));

	elgamal->setKey(pk_shared);
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
*   Send encrypted message to other party
*/
void Party::send_msg_enc(shared_ptr<AsymmetricCiphertext> c_m) {
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
*   Send encrypted template to other party
*/
void Party::send_template(Template_enc T_enc) {
  pair<int, int> size = T_enc.size();

  string T_enc_sendable;

  try {
    for(int i=0; i<size.first; i++) {
      string vector;

      for(int j=0; j<size.second; j++) {
        shared_ptr<AsymmetricCiphertext> elem = T_enc.get_elem(i,j);
        shared_ptr<AsymmetricCiphertextSendableData> elem_sendable = ((ElGamalOnGroupElementCiphertext*) elem.get())->generateSendableData();
        string elem_sendable_string = c_m_sendable->toString();
        
      }
    }
  } catch (const logic_error& e) {
			// Log error message in the exception object
			cerr << e.what();
	}
}
