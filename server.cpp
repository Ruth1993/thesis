#include <iostream>
#include <vector>
#include <algorithm>
#include <stdlib.h>
#include <array>
#include <gmp.h>
#include <gmpxx.h>
#include <chrono>

#include "server.hpp"
#include "template.hpp"

using namespace std;

//add random table entry
void Server::store_table() {

}

shared_ptr<Template_enc> Server::fetch_table() {

}

vector<shared_ptr<AsymmetricCiphertext>> compare(AsymmetricCiphertext* cap_s_enc, biginteger t, biginteger max_s) {
	vector<shared_ptr<AsymmetricCiphertext>> cap_c_enc;

	auto g = dlog->getGenerator();

	//first compute g^-t
	shared_ptr<GroupElement> g_inv = dlog->getInverse(g.get());

	for(int i=0; i<=max_s-t; i++) {

	}
}

int main() {


	return 0;
}
