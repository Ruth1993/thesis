#include <iostream>
#include <stdlib.h>
//#include <../libscapi/include/primitives/Dlog.hpp>
#include <../libscapi/include/mid_layer/AsymmetricEnc.hpp>
#include <../libscapi/include/mid_layer/ElGamalEnc.hpp>

using namespace std;

DlogGroup* dlog = new OpenSSLDlogECF2m("../libscapi/include/configFiles/NISTEC.txt", "K-233");
shared_ptr<DlogGroup> dlog2 = make_shared<OpenSSLDlogECF2m>();

//Create an ElGamalOnGroupElement encryption object
ElGamalOnGroupElementEnc elGamal1(dlog);
ElGamalOnGroupElementEnc elGamal2(dlog);

//Generate a keyPair using the ElGamal object
auto pair1 = elGamal1.generateKey();
auto pair2 = elGamal2.generateKey();

//Publish your public key
Publish(pair1.first);
Publish(pair2.first);

//Set private key and party2's public key
elGamal1.setKey(pair2.first, pair1.second);
elGamal2.setKey(pair1.first, pair2.second);

int main() {

//Create a GroupElementPlaintext to encrypt and encrypt the plaintext
GroupElementPlaintext plaintext(dlog->createRandomElement());
read_plaintext = (GroupElementPlaintext*)plaintext.get().getElement();

cout << "Plaintext: " << read_plaintext << endl;

AsymmetricCiphertext cipher = elGamal1.encrypt(plaintext);

cout << "Ciphertext: " << cipher << endl;

//Decrypt
shared_ptr<Plaintext> plaintext2 = elGamal2.decrypt(cipher);
read_plaintext2 = (GroupElementPlaintext*)plaintext2.get().getElement();

cout << "Plaintext: " << plaintext2 << endl;

return 0;

}
