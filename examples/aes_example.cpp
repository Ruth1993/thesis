#include <vector>

#include "../libscapi/include/mid_layer/OpenSSLSymmetricEnc.hpp"

vector<unsigned char> int_to_byte(int a) {
  vector<unsigned char> result(4);

  for(int i=0; i<4; i++) {
    result[i] = (a >> (8*(3-i)));
  }

  return result;
}

int byte_to_int(vector<unsigned char> vec) {
  int result = 0;

  for(int i=0; i<4; i++) {
    result = (result << 8) + vec[i];
  }

  return result;
}

int main() {
  OpenSSLCTREncRandomIV encryptor("AES");

  //Generate a secret key using the created object and set it
  SecretKey key = encryptor.generateKey(128);
  encryptor.setKey(key);

  //Get a plaintext to encrypt and encrypt the plaintext_ge
  vector<unsigned char> vec = int_to_byte(1);

  ByteArrayPlaintext p1(vec);
  shared_ptr<SymmetricCiphertext> cipher = encryptor.encrypt(&p1);

  shared_ptr<Plaintext> p2 = encryptor.decrypt(cipher.get());

  cout << "Plaintext before conversion to plaintext object: " << byte_to_int(vec) << endl;
  cout << "Plaintext before encryption: " << byte_to_int(p1.getText()) << endl;
  cout << "Ciphertext: " << ((ByteArraySymCiphertext *)cipher.get())->toString() << endl;
  cout << "Plaintext after decryption: " << byte_to_int(((ByteArrayPlaintext *)p2.get())->getText()) << endl;

  return 0;
}
