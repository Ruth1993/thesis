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
	auto h = dlog->createRandomElement();
	// multiply elements
	auto gMult = dlog->multiplyGroupElements(g1.get(), h.get());

  //ElGamal stuff
  ElGamalOnGroupElementEnc elGamal1(dlog);
	ElGamalOnGroupElementEnc elGamal2(dlog);

  auto pair1 = elGamal1.generateKey();
  auto pair2 = elGamal2.generateKey();

  elGamal1.setKey(pair2.first, pair1.second);
	elGamal2.setKey(pair1.first, pair2.second);

  GroupElementPlaintext p1(h);

  shared_ptr<AsymmetricCiphertext> cipher = elGamal1.encrypt(make_shared<GroupElementPlaintext>(p1));
	shared_ptr<Plaintext> plaintext = elGamal2.decrypt(cipher.get());

	//GroupElement plaintext_ge = ((((GroupElementPlaintext*)plaintext.get())->getElement()).get());
	//(((GroupElementPlaintext*)plaintext.get())->getElement())).get()
	//((((GroupElementPlaintext*)plaintext.get())->getElement()).get())->getElementValue()
	//shared_ptr<GroupElement> pl = ((GroupElementPlaintext) plaintext.get()).getElement();

	OpenSSLZpSafePrimeElement* element = ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)plaintext.get())->getElement()).get());

	cout << "generator value is:              " << ((OpenSSLZpSafePrimeElement *)g.get())->getElementValue() << endl;
	cout << "exponentiate value r is:          " << r << endl;
	cout << "exponentiation result is:       " << ((OpenSSLZpSafePrimeElement *)g1.get())->getElementValue() << endl;
	cout << "random element h is:       " << ((OpenSSLZpSafePrimeElement *)h.get())->getElementValue() << endl;
	cout << "element multplied by expresult: " << ((OpenSSLZpSafePrimeElement *)gMult.get())->getElementValue() << endl;
	cout << "decrypted ciphertext is: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)plaintext.get())->getElement()).get())->getElementValue() << endl;
	//cout << "encryption and decryption succeedded" << plaintext==(h) << endl;
  //cout << "plaintext: " << ((OpenSSLZpSafePrimeElement *)pair.first.get())->getElementValue() << endl;
	return 0;
}
