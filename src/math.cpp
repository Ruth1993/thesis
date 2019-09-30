#include "../include/math.hpp"

biginteger mod(biginteger a, biginteger b) {
	biginteger result = a % b;

	if (a < 0) {
		result = (a % b + b) % b;
	}

	return result;
}