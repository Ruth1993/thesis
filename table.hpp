#ifndef TEMPLATE_H
#define TEMPLATE_H

#include <tuple>

#include "../libscapi/include/primitives/DlogOpenSSL.hpp"
#include "../libscapi/include/mid_layer/ElGamalEnc.hpp"
#include "../libscapi/include/mid_layer/OpenSSLSymmetricEnc.hpp"

using namespace std;

class Table {
private:
  vector<tuple<biginteger, shared_ptr<AsymmetricCiphertext>, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>>>> table;

public:

};

#endif
