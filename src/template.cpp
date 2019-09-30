/*
*	Created using libscapi (see https://crypto.biu.ac.il/SCAPI/)
*	Authors: Ruth Scholten
/*
*	Created using libscapi (see https://crypto.biu.ac.il/SCAPI/)
*	Authors: Ruth Scholten
*/

#include <vector>
#include <math.h>

#include "../include/template.hpp"

using namespace std;

/*
*   Generate random template with scores between min_s and max_s
*/
Template::Template(pair<int, int> size, biginteger min_s, biginteger max_s) {
  k = size.first;
  two_pow_b = size.second;

  for(int i=0; i<k; i++) {
    vector<biginteger> vec_col;

    for(int j=0; j<two_pow_b; j++) {
      // create a random value s_{i,j}
      auto gen = get_seeded_prg();
      biginteger s = getRandomInRange(min_s, max_s, gen.get());

      vec_col.push_back(s);
    }

    T.push_back(vec_col);
  }
}

/*
*   Return 2^b, which is the number of columns in the template
*/
int Template::get_two_pow_b() {
  return two_pow_b;
}

/*
*   Return the number of rows in the template
*/
int Template::get_k() {
  return k;
}

/*
*   Return column in i-th row
*/
vector<biginteger> Template::get_col(int i) {
  return T[i];
}

/*
*   Return element on position (x,y)
*/
biginteger Template::get(int i, int j) {
  return T[i][j];
}

/*
*   Add new column to template
*/
void Template::add_col(vector<biginteger> vec_col) {
  T.push_back(vec_col);
}

/*
*   Add new element to template by appending it to the i'th column
*/
void Template::add_elem(biginteger elem, int i) {
  if(i > size().first) {
    //column doesn't exist yet, so first add column
    vector<biginteger> new_col;
    add_col(new_col);
  }

  vector<biginteger> col = get_col(i);
  col.push_back(elem);
}

void Template::set_elem(biginteger elem, int i, int j) {
  if(i <= size().first && j <= size().second) {
    T[i][j] = elem;
  }
}

/*
*   Print template
*/
void Template::print() {
  cout << "Template: { ";

  for(vector<biginteger> vec_col : T) {
    cout << "{";

    for(int j=0; j<vec_col.size()-1; j++) {
      biginteger s = vec_col[j];
      cout << s << ",";
    }

    cout << vec_col[vec_col.size()-1] << "}, ";
  }

  cout << " }" << endl;
}

/*
*   Return template size (k, 2^b)
*/
pair<int, int> Template::size() {
  return make_pair(T.size(), T[0].size());
}

/*
*   Return template size (k, 2^b)
*/
pair<int, int> Template_enc::size() {
  return make_pair(T_enc.size(), T_enc[0].size());
}

/*
*   Get element on position (x,y)
*/
shared_ptr<AsymmetricCiphertext> Template_enc::get_elem(int i, int j) {
  return T_enc[i][j];
}

vector<shared_ptr<AsymmetricCiphertext>> Template_enc::get_col(int i) {
  return T_enc[i];
}

/*
*   Add new column to encrypted template
*/
void Template_enc::add_col(vector<shared_ptr<AsymmetricCiphertext>> vec_col_enc) {
  T_enc.push_back(vec_col_enc);
}

/*
*   Add new element to encrypted template by appending it to the i'th column
*/
void Template_enc::add_elem(shared_ptr<AsymmetricCiphertext> elem, int i) {
  if(i > size().first) {
    //column doesn't exist yet, so first add column
    vector<shared_ptr<AsymmetricCiphertext>> new_col;
    add_col(new_col);
  }

  vector<shared_ptr<AsymmetricCiphertext>> col = get_col(i);
  col.push_back(elem);
}

/*
*   Set element on position (i,j)
*/
void Template_enc::set_elem(shared_ptr<AsymmetricCiphertext> elem, int i, int j) {
  if(i <= size().first && j <= size().second) {
    T_enc[i][j] = elem;
  }
}

/*
*   Empty constructor for Template_enc
*/
Template_enc::Template_enc() {}

/*
*   Constructor for Template_enc, initializing template with empty encryptions
*/
Template_enc::Template_enc(pair<int, int> size) {
  for(int i=0; i<size.first; i++) {
    vector<shared_ptr<AsymmetricCiphertext>> col;

    for(int j=0; j<size.second; j++) {
      shared_ptr<AsymmetricCiphertext> s_enc;
      col.push_back(s_enc);
    }

    add_col(col);
  }
}

int main_tp() {


  return 0;
}
