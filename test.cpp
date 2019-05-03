#include <gmp.h>
#include <gmpxx.h>
#include <vector>

using namespace std;

int main() {
  vector<mpz_t> t(3);
  vector<mpz_class> g;


for(int i=0; i<t.size(); i++) {
  mpz_init(t[i]);
  mpz_set_ui(t[i], i);
  gmp_printf("t[i]: %Zd \n", t[i]);
}

/*
for(int i=0; i<4; i++) {
  mpz_t s;
  mpz_init(s);
  mpz_set_ui(s, 3);
  g.push_back(s);
  gmp_clear(s);
}*/

mpz_class s;
s = 1;
g.push_back(s);


for(int i=0; i<g.size(); i++) {
  gmp_printf("g[i]: %Zd \n", g[i]);
}

  return 0;
}
