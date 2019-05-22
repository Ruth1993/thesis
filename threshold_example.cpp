#include "../libscapi/include/primitives/DlogOpenSSL.hpp"
#include "../libscapi/include/mid_layer/ElGamalEnc.hpp"
#include <iostream>
#include <vector>

int main(int argc, char* argv[]){
  // initiate a discrete log group
	// (in this case the OpenSSL implementation of the elliptic curve group K-233)
	auto dlog = make_shared<OpenSSLDlogZpSafePrime>(128);

	// get the group generator and order
	auto g = dlog->getGenerator();
	biginteger q = dlog->getOrder();

	// create a random exponent r
	auto gen = get_seeded_prg();
	biginteger r = getRandomInRange(0, q-1, gen.get());

	// exponentiate g in r to receive a new group element
	auto g1 = dlog->exponentiate(g.get(), r);
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
  shared_ptr<GroupElement> h_shared = dlog->multiplyGroupElements(pk_p1->getH(), pk_p2->getH());
  PublicKey pk_shared = ElGamalPublicKey(h_shared);

  elGamal1.setKey(pk_shared, sk_p1);

  GroupElementPlaintext p_m(m);

  shared_ptr<AsymmetricCiphertext> E_m = elGamal1.encrypt(make_shared<GroupElementPlaintext>(p_m));

  //Party 2 does a partial decryption of E(m)
  

	cout << "m:              " << ((OpenSSLZpSafePrimeElement *)m.get())->getElementValue() << endl;
	cout << "shared h:       " << ((OpenSSLZpSafePrimeElement *)h_shared.get())->getElementValue() << endl;
	cout << "random element h is:       " << ((OpenSSLZpSafePrimeElement *)h.get())->getElementValue() << endl;
	cout << "element multplied by expresult: " << ((OpenSSLZpSafePrimeElement *)gMult.get())->getElementValue() << endl;
	cout << "decrypted ciphertext is: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)plaintext.get())->getElement()).get())->getElementValue() << endl;
	//cout << "encryption and decryption succeedded" << plaintext==(h) << endl;
  //cout << "plaintext: " << ((OpenSSLZpSafePrimeElement *)pair.first.get())->getElementValue() << endl;
	return 0;
}
