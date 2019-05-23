#include "../libscapi/include/primitives/DlogOpenSSL.hpp"
#include "../libscapi/include/mid_layer/ElGamalEnc.hpp"
#include <iostream>
#include <vector>

int main(int argc, char* argv[]){
  // initiate a discrete log group
	// (in this case the OpenSSL implementation of the elliptic curve group K-233)
	auto dlog = make_shared<OpenSSLDlogZpSafePrime>(128);

	// create a random group element
	auto m = dlog->createRandomElement();

  //ElGamal stuff
  ElGamalOnGroupElementEnc elGamal1(dlog);
	ElGamalOnGroupElementEnc elGamal2(dlog);

  auto pair1 = elGamal1.generateKey();
  auto pair2 = elGamal2.generateKey();

  shared_ptr<PublicKey> pk_p1 = pair1.first;
  shared_ptr<PrivateKey> sk_p1 = pair1.second;

  shared_ptr<PublicKey> pk_p2 = pair2.first;
  shared_ptr<PrivateKey> sk_p2 = pair2.second;

  elGamal1.setKey(pk_p1, sk_p1);
  elGamal2.setKey(pk_p2, sk_p2);

  //Party 1 computes shared public key of both parties:
  shared_ptr<GroupElement> h_shared1 = dlog->exponentiate(((ElGamalPublicKey*) pk_p2.get())->getH().get(), ((ElGamalPrivateKey*) sk_p1.get())->getX());
  shared_ptr<PublicKey> pk_shared1 = make_shared<ElGamalPublicKey>(ElGamalPublicKey(h_shared1));

  elGamal1.setKey(pk_shared1);

  GroupElementPlaintext p_m(m);

  shared_ptr<AsymmetricCiphertext> E_m = elGamal1.encrypt(make_shared<GroupElementPlaintext>(p_m));

	//Party 2 computes shared public key of both parties
	//assert h_stared1 == h_shared2
	shared_ptr<GroupElement> h_shared2 = dlog->exponentiate(((ElGamalPublicKey*) pk_p1.get())->getH().get(), ((ElGamalPrivateKey*) sk_p2.get())->getX());

  //Party 2 does a partial decryption of E(m) by computing c_1^sk_p2
	shared_ptr<GroupElement> c_1_prime = dlog->exponentiate(((ElGamalOnGroupElementCiphertext*) E_m.get())->getC1().get(), ((ElGamalPrivateKey*) sk_p2.get())->getX());
	ElGamalOnGroupElementCiphertext E_m_prime = ElGamalOnGroupElementCiphertext(c_1_prime, ((ElGamalOnGroupElementCiphertext*) E_m.get())->getC2());

	//Now Party 1 does the final decryption Step
	shared_ptr<Plaintext> plaintext = elGamal1.decrypt(&E_m_prime);


	cout << "m:              " << ((OpenSSLZpSafePrimeElement *)m.get())->getElementValue() << endl;
	cout << "shared h for party 1:       " << ((OpenSSLZpSafePrimeElement *)h_shared1.get())->getElementValue() << endl;
	cout << "shared h for party 2:       " << ((OpenSSLZpSafePrimeElement *)h_shared2.get())->getElementValue() << endl;
	cout << "decrypted ciphertext is: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)plaintext.get())->getElement()).get())->getElementValue() << endl;

	return 0;
}
