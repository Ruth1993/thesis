#ifndef PARTY_H
#define PARTY_H

#include <string>

#include "../../libscapi/include/mid_layer/OpenSSLSymmetricEnc.hpp"
#include "../../libscapi/include/primitives/DlogOpenSSL.hpp"
#include "../../libscapi/include/mid_layer/ElGamalEnc.hpp"
#include "../../libscapi/include/infra/Scanner.hpp"
#include "../../libscapi/include/infra/ConfigFile.hpp"
#include "../../libscapi/include/comm/Comm.hpp"
#include "../../libscapi/include/infra/Common.hpp"
#include "../../libscapi/include/interactive_mid_protocols/CommitmentScheme.hpp"
#include "../../libscapi/include/interactive_mid_protocols/CommitmentSchemePedersen.hpp"

#include <boost/thread/thread.hpp>

#include "template.hpp"

class Party {
protected:
  //Channel object
  shared_ptr<CommParty> channel;

  //ElGamal and AES objects
  shared_ptr<OpenSSLCTREncRandomIV> aes_enc;
  shared_ptr<OpenSSLDlogZpSafePrime> dlog;
  shared_ptr<ElGamalOnGroupElementEnc> elgamal;

  shared_ptr<PublicKey> pk_own;
  shared_ptr<PrivateKey> sk_own;
  shared_ptr<PublicKey> pk_shared;

  //Protocol parameters
  const pair<int, int> template_size = make_pair(3,4); //assert sqrt(template_size.second) == integer
  const int min_s = 0;
  const int max_s = 10;
  const biginteger max_S = template_size.first * max_s;

public:
  vector<unsigned char> int_to_byte(int a);

  int byte_to_int(vector<unsigned char> vec);

  void pad(vector<unsigned char> &input, int bytes);

  shared_ptr<PublicKey> recv_pk();

  void key_setup(shared_ptr<PublicKey> pk_other);

  void send_msg(string msg);

  void send_msg(int msg);

  void send_pk();

  void send_elgamal_msg(shared_ptr<AsymmetricCiphertext> c_m);

  void send_aes_msg(shared_ptr<SymmetricCiphertext> c_m);

  void send_vec_enc(vector<shared_ptr<AsymmetricCiphertext>> vec_enc);

  void send_template(shared_ptr<Template_enc> T_enc);

  string recv_msg();

  shared_ptr<AsymmetricCiphertext> recv_elgamal_msg();

  shared_ptr<SymmetricCiphertext> recv_aes_msg();

  vector<shared_ptr<AsymmetricCiphertext>> recv_vec_enc(int size);

  shared_ptr<Template_enc> recv_template();

  biginteger random_bit();

  biginteger random_bitstring(int bits);

  int bct_p1();

  int bct_p2();

  void act_p1(int n, int l);

  void act_p2(int n, int l);
};

#endif
