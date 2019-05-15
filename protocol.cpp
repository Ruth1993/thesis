#include <iostream>

#include "sensor.hpp"
#include "server.hpp"

using namespace std;

int main() {
	auto dlog = make_shared<OpenSSLDlogZpSafePrime>(128);

	Sensor ss(dlog);
	Server sv(dlog);

	for(int i=0; i<4; i++) {
		tuple<int, shared_ptr<Template_enc>, pair<shared_ptr<AsymmetricCiphertext>, shared_ptr<SymmetricCiphertext>>> enrollment = ss.enroll(make_pair(3, 2));
		sv.store_table(get<0>(enrollment), get<1>(enrollment), get<2>(enrollment));
	}

	return 0;
}
