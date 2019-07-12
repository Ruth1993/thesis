#include "../../libscapi/include/comm/Comm.hpp"
#include "../../libscapi/include/interactive_mid_protocols/CommitmentScheme.hpp"
#include "../../libscapi/include/interactive_mid_protocols/CommitmentSchemePedersen.hpp"

#include "../../libscapi/include/mid_layer/OpenSSLSymmetricEnc.hpp"
#include "../../libscapi/include/primitives/DlogOpenSSL.hpp"
#include "../../libscapi/include/mid_layer/ElGamalEnc.hpp"

#include <boost/thread/thread.hpp>

#include <vector>

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

    SocketPartyData p2 = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8001);
    SocketPartyData p1 = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8000);

    shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, p2, p1);

    //setup ElGamal communication
		//First read dlog parameters from file
		ConfigFile cf("dlog_params.txt");
		string p = cf.Value("", "p");
		string g = cf.Value("", "g");
		string q = cf.Value("", "q");
    auto dlog = make_shared<OpenSSLDlogZpSafePrime>(q, g, p);
    ElGamalOnGroupElementEnc elgamal(dlog);
    auto pair = elgamal.generateKey();
    elgamal.setKey(pair.first, pair.second);

    try {
      channel->join(500, 5000);
      cout << "channel established" << endl;

      vector<byte> resMsg;
      channel->readWithSizeIntoVector(resMsg);
      const byte * uc = &(resMsg[0]);
      string resMsgStr(reinterpret_cast<char const*>(uc), resMsg.size());
      cout << "message: " << resMsgStr << endl;

			//Receive public key from party 1
			shared_ptr<KeySendableData> pk_p1_sendable = make_shared<ElGamalPublicKeySendableData>(dlog->getGenerator()->generateSendableData());
      vector<byte> raw_msg;
      channel->readWithSizeIntoVector(raw_msg);
			pk_p1_sendable->initFromByteVector(raw_msg);
			shared_ptr<PublicKey> pk_p1 = elgamal.reconstructPublicKey(pk_p1_sendable.get());
			shared_ptr<GroupElement> h = ((ElGamalPublicKey*) pk_p1.get())->getH();
			cout << "h: " << ((OpenSSLZpSafePrimeElement *)h.get())->getElementValue() << endl;

			//Set pk_p1 to public key and encrypt random element
			elgamal.setKey(pk_p1, pair.second);
			auto m = dlog->createRandomElement();
			cout << "m: " << ((OpenSSLZpSafePrimeElement *)m.get())->getElementValue() << endl;
			GroupElementPlaintext p_m(m);
			shared_ptr<AsymmetricCiphertext> c_m = elgamal.encrypt(make_shared<GroupElementPlaintext>(p_m));

			//Send [m] to party 1
			shared_ptr<AsymmetricCiphertextSendableData> c_m_sendable = ((ElGamalOnGroupElementCiphertext*) c_m.get())->generateSendableData();
			string c_m_sendable_string = c_m_sendable->toString();
			channel->writeWithSize(c_m_sendable_string);

      /*auto dlog = make_shared<OpenSSLDlogECF2m>();
      shared_ptr<CmtReceiver> receiver = make_shared<CmtPedersenReceiver>(channel, dlog);

      auto commitment = receiver->receiveCommitment();
      auto result = receiver->receiveDecommitment(0);
      if (result == NULL) {
        cout << "commitment failed" << endl;
      } else {
        cout << "the committed value is:" << result->toString() << endl;
      }*/
    } catch (const logic_error& e) {
    		// Log error message in the exception object
    		cerr << e.what();
    }

    return 0;
}
