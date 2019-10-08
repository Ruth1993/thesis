#ifndef MATH_H
#define MATH_H

/*
*	Created using libscapi (see https://crypto.biu.ac.il/SCAPI/)
*	Authors: Ruth Scholten
*/

#include "../../libscapi/include/infra/Common.hpp"

biginteger mod(biginteger a, biginteger b);

vector<unsigned char> int_to_byte(int a);

int byte_to_int(vector<unsigned char> vec);

vector<vector<int>> permutation_matrix(int size);

int main_math();

void print_permutation_matrix(vector<vector<int>> A);

#endif
