#include <gmp.h>
#include <array>
#include <math.h>

using namespace std;

class Template {
private:
  const static int b = 2;
  const static int k = 3;

  const static int col = pow(2, b);

public:
  array<array<mpz_t, col>, k> T;

  Template(mpz_class min_s, mpz_class max_s);

  //Template();

  void print();
};

int main();
