
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
*	Get \sigma(m) from table
*/
Signature Table::get_sig_m(int u) {
	Signature sig_m;

	for (Table_Entry entry : table) {
		if (entry.u == u) {
			sig_m = entry.sig_m;
		}
	}

	return sig_m;
}

/*
*	Get \sigma(n) from table
*/
Signature Table::get_sig_n(int u) {
	Signature sig_n;

	for (Table_Entry entry : table) {
		if (entry.u == u) {
			sig_n = entry.sig_n;
		}
	}

	return sig_n;
}

/*
*	Get public key y (used for signatures) from table
*/
shared_ptr<GroupElement> Table::get_y(int u) {
	shared_ptr<GroupElement> y;

	for (Table_Entry entry : table) {
		if (entry.u == u) {
			y = entry.y;
		}
	}

	return y;
}

/*
*   Add entry to table
*/
void Table::add_entry(int u, shared_ptr<Template_enc> T_enc, shared_ptr<AsymmetricCiphertext> k_enc, shared_ptr<SymmetricCiphertext> aes_k_1, Signature sig_m, Signature sig_n, shared_ptr<GroupElement> y) {
  Table_Entry entry = {u, T_enc, k_enc, aes_k_1, sig_m, sig_n, y};
  table.push_back(entry);
}

/*
*   Replace old key pair by new key pair
*/
void Table::change_key_pair(int u, shared_ptr<AsymmetricCiphertext> k_enc, shared_ptr<SymmetricCiphertext> aes_k_1, Signature sig_n, shared_ptr<GroupElement> y) {
  for(Table_Entry entry : table) {
    if(entry.u == u) {
      entry.k_enc = k_enc;
      entry.aes_k_1 = aes_k_1;
	  entry.sig_n = sig_n;
	  entry.y = y;
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
