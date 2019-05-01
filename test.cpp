#include <gmp.h>
#include <vector>

int main() {
  std::vector<mpz_t> t(3);

for(int i=0; i<t.size(); i++) {
  mpz_init(t[i]);
  mpz_set_ui(t[i], i);
  gmp_printf("t[i]: %Zd \n", t[i]);
}



  return 0;
}
