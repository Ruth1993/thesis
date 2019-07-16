#ifndef PARTY_H
#define PARTY_H

#include "../libscapi/include/mid_layer/OpenSSLSymmetricEnc.hpp"
#include "../libscapi/include/primitives/DlogOpenSSL.hpp"
#include "../libscapi/include/mid_layer/ElGamalEnc.hpp"
#include "../libscapi/include/infra/Scanner.hpp"
#include "../libscapi/include/infra/ConfigFile.hpp"
#include "../libscapi/include/comm/Comm.hpp"
#include "../libscapi/include/infra/Common.hpp"
#include "../libscapi/include/interactive_mid_protocols/CommitmentScheme.hpp"
#include "../libscapi/include/interactive_mid_protocols/CommitmentSchemePedersen.hpp"

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

public:
  shared_ptr<PublicKey> recv_pk();

  void key_setup(shared_ptr<PublicKey> pk_other);

  void send_pk();

  void send_msg_enc(shared_ptr<AsymmetricCiphertext> c_m);

  void send_template();
};

#endif
