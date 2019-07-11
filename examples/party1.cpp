#include "../../libscapi/include/comm/Comm.hpp"
#include "../../libscapi/include/interactive_mid_protocols/CommitmentScheme.hpp"
#include "../../libscapi/include/interactive_mid_protocols/CommitmentSchemePedersen.hpp"

#include "../../libscapi/include/mid_layer/OpenSSLSymmetricEnc.hpp"
#include "../../libscapi/include/primitives/DlogOpenSSL.hpp"
#include "../../libscapi/include/mid_layer/ElGamalEnc.hpp"

#include <boost/thread/thread.hpp>

void print_send_message(const string  &s, int i) {
	cout << "sending message number " << i << " message: " << s << endl;
}
void print_recv_message(const string &s, int i) {
	cout << "received message number " << i << " message: " << s << endl;
}

void send_messages(shared_ptr<CommParty> channel, string * messages, int start, int end) {
	for (int i = start; i < end; i++) {
		auto s = messages[i];
		print_send_message(s, i);
		channel->write((const byte *)s.c_str(), s.size());
	}
}

void recv_messages(shared_ptr<CommParty> channel, string * messages, int start, int end, byte * buffer, int expectedSize) {
	channel->read(buffer, expectedSize);
	// the size of all strings is 2. Parse the message to get the original strings
	int j = 0;
	for (int i = start; i < end; i++, j++) {
		auto s = string(reinterpret_cast<char const*>(buffer+j*2), 2);
		print_recv_message(s, i);
		messages[i] = s;
	}
}

int main(int argc, char* argv[]) {

    boost::asio::io_service io_service;

    SocketPartyData p1 = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8000);
    SocketPartyData p2 = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8001);

    shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, p1, p2);

    //setup ElGamal communication
    auto dlog = make_shared<OpenSSLDlogZpSafePrime>(128);
    ElGamalOnGroupElementEnc elgamal(dlog);
    auto pair = elgamal.generateKey();
    elgamal.setKey(pair.first, pair.second);

    try {
      channel->join(500, 5000);
      cout << "channel established" << endl;

      string longMessage = "Hi, this is a long message to test the writeWithSize approach";
      channel->writeWithSize(longMessage);

      shared_ptr<KeySendableData> pk_sendable = pair.first->generateSendableData();

      chanell->writeWithSize(pk_sendable->getEncoded());

      /*auto dlog = make_shared<OpenSSLDlogECF2m>();
      shared_ptr<CmtCommitter> committer = make_shared<CmtPedersenCommitter>(channel, dlog);

      auto val = committer->sampleRandomCommitValue();
      cout << "the committed value is:" << val->toString() << endl;
      committer->commit(val, 0);
      committer->decommit(0);*/
    } catch (const logic_error& e) {
    		// Log error message in the exception object
    		cerr << e.what();
    }

    return 0;
}
