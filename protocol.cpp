#include <iostream>

#include "sensor.hpp"
#include "server.hpp"

using namespace std;

int main() {
	Sensor ss;
	Server sv;

	tuple<int, shared_ptr<Template_enc>, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>>> = ss.enroll(make_pair(3, 2));


	return 0;
}
