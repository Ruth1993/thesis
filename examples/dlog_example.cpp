/*
* Copyright (c) 2016 LIBSCAPI (http://crypto.biu.ac.il/SCAPI)
*/

#include "../../libscapi/include/primitives/DlogOpenSSL.hpp"
#include "../../libscapi/include/mid_layer/ElGamalEnc.hpp"
#include "../../libscapi/include/infra/Common.hpp"
#include <iostream>
#include <vector>

int main(int argc, char* argv[]){
  // initiate a discrete log group
	// (in this case the OpenSSL implementation of the elliptic curve group K-233)
	auto dlog1 = make_shared<OpenSSLDlogZpSafePrime>(128);
	auto dlog = make_shared<OpenSSLDlogECF2m>();

	// get the group generator and order
	auto g = dlog->getGenerator();
	biginteger q = dlog->getOrder();

	// create a random exponent r
	auto gen = get_seeded_prg();
	biginteger x = getRandomInRange(0, q-1, gen.get());

	// exponentiate g in r to receive a new group element
	auto g1 = dlog->exponentiate(g.get(), x);
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

	biginteger r = getRandomInRange(0, q-1, gen.get());
	/*cout << "r: " << r << endl;
	size_t size = bytesCount(r);
	cout << "size: " << static_cast<int>(size) << endl;
	byte* r_bytes = new byte[size];
	encodeBigInteger(r, r_bytes, size);
	print_byte_array(r_bytes, static_cast<int>(size), "byte: ");*/

	auto id = dlog->getIdentity();
	GroupElementPlaintext p_id(id);
	shared_ptr<AsymmetricCiphertext> c_res = elGamal1.encrypt(make_shared<GroupElementPlaintext>(p_id));
	biginteger a = 2;
	biginteger res = 1;


	/*while(r > 0) {
		if(r & 1) {
				c_res = elGamal1.multiply(c_res.get(), cipher.get());
				res = res*a;
				cout << "res*a = " << res << endl;
		}

		cipher = elGamal1.multiply(cipher.get(), cipher.get());
		a = a*a;
		cout << "a*a = " << a << endl;
		r >>= 1;
	}

	cout << "res: " << res << endl;*/

	biginteger r_acc = getRandomInRange(0, (biginteger)pow(2, 5), gen.get());
	cout << "r': " << r_acc << endl;

	/*cout << "generator value is:              " << ((OpenSSLZpSafePrimeElement *)g.get())->getElementValue() << endl;
	cout << "exponentiate value r is:          " << r << endl;
	cout << "exponentiation result is:       " << ((OpenSSLZpSafePrimeElement *)g1.get())->getElementValue() << endl;
	cout << "random element h is:       " << ((OpenSSLZpSafePrimeElement *)h.get())->getElementValue() << endl;
	cout << "element multiplied by expresult: " << ((OpenSSLZpSafePrimeElement *)gMult.get())->getElementValue() << endl;
	cout << "decrypted ciphertext is: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)plaintext.get())->getElement()).get())->getElementValue() << endl;
	//cout << "encryption and decryption succeedded" << plaintext==(h) << endl;
  //cout << "plaintext: " << ((OpenSSLZpSafePrimeElement *)pair.first.get())->getElementValue() << endl;*/

	//delete[] r_bytes;

	return 0;
}
