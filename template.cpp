#include <gmp.h>
#include <gmpxx.h>
#include <vector>
#include <math.h>
#include <chrono>

#include "template.hpp"
#include "elgamal.hpp"

using namespace std;

//Generate random template with scores between min_s and max_s
Template::Template(mpz_class min_s, mpz_class max_s) {
  for(int i=0; i<k; i++) {
    for(int j=0; j<col; j++) {
      mpz_init(T[i][j]);

      unsigned long seed = chrono::system_clock::now().time_since_epoch().count();
      gmp_randstate_t rstate;
      gmp_randinit_mt(rstate);
      gmp_randseed_ui(rstate, seed);

      mpz_urandomm(T[i][j], rstate, max_s.get_mpz_t());
      mpz_add(T[i][j], T[i][j], min_s.get_mpz_t());
    }
  }
}

void Template::print() {
  gmp_printf("{");

  for(int i=0; i<k; i++) {
    gmp_printf("{");

    for(int j=0; j<col; j++) {
      gmp_printf("%Zd,", T[i][j]);
    }

    gmp_printf("}");
  }

  gmp_printf("} \n");
}

int main() {
  Template Tem(0,1);
  Tem.print();

  return 0;
}
