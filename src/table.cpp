
#include "../include/table.hpp"

using namespace std;

/*
*   Fetch [[T_u]] from table
*/
shared_ptr<Template_enc> Table::get_T_enc(int u) {
  shared_ptr<Template_enc> T_enc;

  for(Table_Entry entry : table) {
    if(entry.u == u) {
      T_enc = entry.T_enc;
    }
  }

  return T_enc;
}

/*
*   Get key pair ([[k]], AES_k(1)) from table
*/
pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> Table::get_key_pair(int u) {
  pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> key_pair;

  for(Table_Entry entry : table) {
    if(entry.u == u) {
      key_pair = make_pair(entry.k_enc, entry.aes_k_1);
    }
  }

  return key_pair;
}

/*
*   Add entry to table
*/
void Table::add_entry(int u, shared_ptr<Template_enc> T_enc, shared_ptr<AsymmetricCiphertext> k_enc, shared_ptr<SymmetricCiphertext> aes_k_1) {
  Table_Entry entry = {u, T_enc, k_enc, aes_k_1};
  table.push_back(entry);
}

/*
*   Replace old key pair by new key pair
*/
void Table::change_key_pair(int u, shared_ptr<AsymmetricCiphertext> k_enc, shared_ptr<SymmetricCiphertext> aes_k_1) {
  for(Table_Entry entry : table) {
    if(entry.u == u) {
      entry.k_enc = k_enc;
      entry.aes_k_1 = aes_k_1;
    }
  }
}

/*
*   Remove entry from table
*/
void Table::remove_entry(int u) {
  for(int i=0; i<table.size(); i++) {
    if(table[i].u == u) {
      table.erase(table.begin()+i);
    }
  }
}

/*
* Print table size
*/
int Table::size() {
  return table.size();
}
