#ifndef TABLE_H
#define TABLE_H

#include <vector>

#include "template.hpp"

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
  };

  vector<Table_Entry> table;

public:
  shared_ptr<Template_enc> get_T_enc(int u);

  pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> get_key_pair(int u);

  void add_entry(int u, shared_ptr<Template_enc> T_enc, shared_ptr<AsymmetricCiphertext> k_enc, shared_ptr<SymmetricCiphertext> aes_k_1);

  void change_key_pair(int u, shared_ptr<AsymmetricCiphertext> k_enc, shared_ptr<SymmetricCiphertext> aes_k_1);

  void remove_entry(int u);

  int size();
};

#endif
