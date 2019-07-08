#ifndef TEMPLATE_H
#define TEMPLATE_H

#include <gmp.h>
#include <vector>
#include <math.h>

#include "../libscapi/include/primitives/DlogOpenSSL.hpp"
#include "../libscapi/include/mid_layer/ElGamalEnc.hpp"

using namespace std;

class Template {
private:
  int b;
  int k;

public:
  vector<vector<biginteger>> T;

  Template(pair<int, int> size, biginteger min_s, biginteger max_s);

  Template();

  int get_b();

  int get_k();

  vector<biginteger> get_col(int i);

  biginteger get(int i, int j);

  void print();

  pair<int, int> size();
};

class Template_enc {
  public:
    vector<vector<shared_ptr<AsymmetricCiphertext>>> T_enc;

  void add_col(vector<shared_ptr<AsymmetricCiphertext>> vec_col_enc);

  pair<int, int> size();

  shared_ptr<AsymmetricCiphertext> get_elem(int i, int j);
};

int main_tp();

#endif
