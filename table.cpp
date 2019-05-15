
#include "table.hpp"

using namespace std;

shared_ptr<AsymmetricCiphertext> Table::get_T_enc(int u) {
  shared_ptr<AsymmetricCiphertext> T_enc;

  for(Table_Entry entry : table) {
    if(entry.u == u) {
      T_enc = entry.T_enc;
    }
  }

  return T_enc;
}

pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> Table::get_key_pair(int u) {
  pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>> key_pair;

  for(Table_Entry entry : table) {
    if(entry.u == u) {
      key_pair = make_pair(entry.K_enc, entry.K_aes);
    }
  }

  return key_pair;
}

void Table::add_entry(int u, shared_ptr<AsymmetricCiphertext> T_enc, shared_ptr<AsymmetricCiphertext> K_enc, shared_ptr<SymmetricCiphertext> K_aes) {
  Table_Entry entry = {u, T_enc, K_enc, K_aes};
  table.push_back(entry);
}

void Table::change_key_pair(int u, shared_ptr<AsymmetricCiphertext> K_enc, shared_ptr<SymmetricCiphertext> K_aes) {
  for(Table_Entry entry : table) {
    if(entry.u == u) {
      entry.K_enc = K_enc;
      entry.K_aes = K_aes;
    }
  }
}

void Table::remove_entry(int u) {
  for(int i=0; i<table.size(); i++) {
    if(table[i].u == u) {
      table.erase(table.begin()+i);
    }
  }
}
