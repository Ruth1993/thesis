#include <gmp.h>
#include <array>
#include <math.h>

#include "template.hpp"

using namespace std;

Template::Template() {
  const int col = pow(2, b);

  array<array<mpz_t, col>, k> templ;

  for(int i=0; i<k; i++) {
    for(int j=0; j<col; j++) {
      mpz_init(templ[i][j]);
    }
  }
}

int main() {
  Template Tem;
  mpz_set_ui(Tem.T[0][0], 2);

  gmp_printf("T[0][0]: %Zd \n", Tem.T[0][0]);

  return 0;
}
