#include <gmp.h>
#include <array>

using namespace std;

class Template {
private:
  const static int b = 2;
  const static int col = 4;
  const static int k = 3;

  array<array<mpz_t, col>, k> T;

public:
  Template();
};

int main();
