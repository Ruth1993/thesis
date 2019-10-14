/*
*	Created using libscapi (see https://crypto.biu.ac.il/SCAPI/)
*	Authors: Ruth Scholten
*/

#ifndef TABLE_H
#define TABLE_H

#include <vector>

#include "template.hpp"
#include "schnorrsig.hpp"

#include "../../libscapi/include/primitives/DlogOpenSSL.hpp"
#include "../../libscapi/include/mid_layer/ElGamalEnc.hpp"
#include "../../libscapi/include/mid_layer/OpenSSLSymmetricEnc.hpp"

using namespace std;

class Table {
private:
  struct Table_Entry {
    int u;
    shared_ptr<Template_enc> T_enc;
    shared_ptr<AsymmetricCiphertext> k_enc;
    shared_ptr<SymmetricCiphertext> aes_k_1;
	Signature sig_m;
	Signature sig_n;
	shared_ptr<GroupElement> y;
  };

  vector<Table_Entry> table;

public:
  shared_ptr<Template_enc> get_T_enc(int u);

  pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> get_key_pair(int u);

  Signature get_sig_m(int u);

  Signature get_sig_n(int u);

  shared_ptr<GroupElement> get_y(int u);

  void add_entry(int u, shared_ptr<Template_enc> T_enc, shared_ptr<AsymmetricCiphertext> k_enc, shared_ptr<SymmetricCiphertext> aes_k_1, Signature sig_m, Signature sig_n, shared_ptr<GroupElement> y);

  void change_key_pair(int u, shared_ptr<AsymmetricCiphertext> k_enc, shared_ptr<SymmetricCiphertext> aes_k_1, Signature sig_n, shared_ptr<GroupElement> y);

  void remove_entry(int u);

  int size();
};

#endif
