#include <vector>
#include <math.h>

#include "template.hpp"

using namespace std;

//Generate random template with scores between min_s and max_s
Template::Template(int kk, int bb, biginteger min_s, biginteger max_s) {
  b = bb;
  k = kk;

  int col = pow(2, b);

  for(int i=0; i<k; i++) {
    vector<biginteger> vec_col;

    for(int j=0; j<col; j++) {
      // create a random value s_{i,j}
      auto gen = get_seeded_prg();
      biginteger s = getRandomInRange(min_s, max_s, gen.get());

      vec_col.push_back(s);
    }

    T.push_back(vec_col);
  }
}

Template::Template() {
  Template(3, 2, 0, 10);
}

int Template::get_b() {
  return b;
}

int Template::get_k() {
  return k;
}

//Get element on position x,y
biginteger Template::get(int i, int j) {
  return T[i][j];
}

void Template::print() {
  cout << "{ ";
  for(vector<biginteger> vec_col : T) {
    cout << "{";
    for(biginteger s : vec_col) {
        cout << s << ",";
    }

    cout << "}, ";
  }

  cout << " }" << endl;
}

//Add new column to encrypted template
void Template_enc::add_col(vector<shared_ptr<AsymmetricCiphertext>> vec_col_enc) {
  T_enc.push_back(vec_col_enc);
}

int main_tp() {
  Template T;
  T.print();

  return 0;
}
