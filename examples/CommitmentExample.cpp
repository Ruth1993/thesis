
/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*
* Copyright (c) 2016 LIBSCAPI (http://crypto.biu.ac.il/SCAPI)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
*
* Libscapi uses several open source libraries. Please see these projects for any further licensing issues.
* For more information , See https://github.com/cryptobiu/libscapi/blob/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*
*/


#include "CommitmentExample.hpp"
#include <stdlib.h>

using namespace std;

CommitmentParams readCommitmentConfig(string config_file) {
	ConfigFile cf(config_file);
	string proverIpStr = cf.Value("", "proverIp");
	string verifierIpStr = cf.Value("", "verifierIp");
	int proverPort = stoi(cf.Value("", "proverPort"));
	int verifierPort = stoi(cf.Value("", "verifierPort"));
	auto proverIp = IpAddress::from_string(proverIpStr);
	auto verifierIp = IpAddress::from_string(verifierIpStr);
	string protocolName = cf.Value("", "protocolName");
	return CommitmentParams(proverIp, verifierIp, proverPort, verifierPort, protocolName);
};

void CommitmentUsage() {
	std::cerr << "Usage: ./libscapi_examples <1(=committer)|2(=receiver)> config_file_path" << std::endl;
}

shared_ptr<CmtCommitter> getCommitter(shared_ptr<CommParty> channel) {
	auto dlog = make_shared<OpenSSLDlogECF2m>();
	shared_ptr<CmtCommitter> sds = make_shared<CmtPedersenCommitter>(channel, dlog);

	return sds;
}

shared_ptr<CmtReceiver> getReceiver(shared_ptr<CommParty> channel) {
	auto dlog = make_shared<OpenSSLDlogECF2m>();
	shared_ptr<CmtReceiver>	sds = make_shared<CmtPedersenReceiver>(channel, dlog);

	return sds;
}

int main(int argc, char* argv[]) {
	//char *p;
	//int side = strtol(argv[1], &p, 10);
	string side = argv[1];
	string configPath = argv[2];

	auto sdp = readCommitmentConfig(configPath);
	boost::asio::io_service io_service;
	SocketPartyData committerParty(sdp.committerIp, sdp.committerPort);
	SocketPartyData receiverParty(sdp.receiverIp, sdp.receiverPort);
	shared_ptr<CommParty> server = (side == "1") ?
		make_shared<CommPartyTCPSynced>(io_service, committerParty, receiverParty) :
		make_shared<CommPartyTCPSynced>(io_service, receiverParty, committerParty);
	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));

	try {
		if (side == "1") {
			server->join(500, 5000); // sleep time=500, timeout = 5000 (ms);
			auto committer = getCommitter(server);
			auto val = committer->sampleRandomCommitValue();
			cout << "the committed value is:" << val->toString() << endl;
			committer->commit(val, 0);
			committer->decommit(0);
		}
		else if (side == "2") {
			server->join(500, 5000); // sleep time=500, timeout = 5000 (ms);
			auto receiver = getReceiver(server);
			auto commitment = receiver->receiveCommitment();
			auto result = receiver->receiveDecommitment(0);
			if (result == NULL) {
				cout << "commitment failed" << endl;
			} else {
				cout << "the committed value is:" << result->toString() << endl;
			}
		}
		else {
			CommitmentUsage();
			return 1;
		}
	}
	catch (const logic_error& e) {
		// Log error message in the exception object
		cerr << e.what();
	}
	io_service.stop();
	t.join();

	return 0;
}
