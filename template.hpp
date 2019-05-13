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

  Template(int bb, int kk, int min_s, int max_s);

  Template();

  int get_b();

  int get_k();

  void print();
};

class Template_enc {
  public:
    vector<vector<shared_ptr<AsymmetricCiphertext>>> T_enc;

  void add_col(vector<shared_ptr<AsymmetricCiphertext>> vec_col_enc);

  void print();
};

int main_tp();
