#include "../../libscapi/include/comm/Comm.hpp"
#include "../../libscapi/include/interactive_mid_protocols/CommitmentScheme.hpp"
#include "../../libscapi/include/interactive_mid_protocols/CommitmentSchemePedersen.hpp"

#include "../../libscapi/include/interactive_mid_protocols/ZeroKnowledge.hpp"
#include "../../libscapi/include/interactive_mid_protocols/SigmaProtocol.hpp"
#include "../../libscapi/include/interactive_mid_protocols/SigmaProtocolDlog.hpp"
#include "../../libscapi/include/interactive_mid_protocols/SigmaProtocolPedersenCommittedValue.hpp"
#include "../../libscapi/include/interactive_mid_protocols/SigmaProtocolPedersenCmtKnowledge.hpp"
#include "../../libscapi/include/interactive_mid_protocols/SigmaProtocolAnd.hpp"

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

    SocketPartyData p2 = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 7880);
    SocketPartyData p1 = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 7831);

    shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, p2, p1);

    //setup ElGamal communication
	//First read dlog parameters from file
	/*ConfigFile cf("dlog_params.txt");
	string p_string = cf.Value("", "p");
	string g_string = cf.Value("", "g");
	string q_string = cf.Value("", "q");
    auto dlog = make_shared<OpenSSLDlogZpSafePrime>(q_string, g_string, p_string);
	auto g = dlog->getGenerator();
    ElGamalOnGroupElementEnc elgamal(dlog);
    auto pair = elgamal.generateKey();
    elgamal.setKey(pair.first, pair.second);*/

    try {
      channel->join(500, 5000);
      cout << "channel established" << endl;

	  //Sigma Dlog AND protocol


      /*vector<byte> resMsg;
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

			//Send vec([[m]]) to party 1
			auto m2 = dlog->createRandomElement();
			cout << "m2: " << ((OpenSSLZpSafePrimeElement *)m2.get())->getElementValue() << endl;
			GroupElementPlaintext p_m2(m2);
			shared_ptr<AsymmetricCiphertext> c_m2 = elgamal.encrypt(make_shared<GroupElementPlaintext>(p_m2));
			vector<shared_ptr<AsymmetricCiphertext>> vec;
			vec.push_back(c_m);
			vec.push_back(c_m2);

			for(shared_ptr<AsymmetricCiphertext> elem : vec) {
				shared_ptr<AsymmetricCiphertextSendableData> elem_sendable = ((ElGamalOnGroupElementCiphertext*) elem.get())->generateSendableData();
				string elem_sendable_string = elem_sendable->toString();
				channel->writeWithSize(elem_sendable_string);
			}*/

			//Zero-knowledge proof stuff
	  /*auto dlog = make_shared<OpenSSLDlogECF2m>("K-233");
	  auto g = dlog->getGenerator();
	  ZKFromSigmaVerifier verifier(channel, make_shared<SigmaDlogVerifierComputation>(dlog, 40, get_seeded_prg()), get_seeded_prg());
	  auto msgA = make_shared<SigmaGroupElementMsg>(dlog->getIdentity()->generateSendableData());
	  auto msgZ = make_shared<SigmaBIMsg>();
	  auto co = dlog->exponentiate(g.get(), 3);
	  shared_ptr<SigmaDlogCommonInput> input = make_shared<SigmaDlogCommonInput>(co);
	  cout << "co: " << ((OpenSSLZpSafePrimeElement*)co.get())->getElementValue() << endl;
	  cout << verifier.verify(input.get(), msgA, msgZ) << endl;*/

		auto dlog = make_shared<OpenSSLDlogECF2m>("K-233");
			auto g = dlog->getGenerator();

			  vector<shared_ptr<SigmaVerifierComputation>> verifiers;

			  biginteger r = 5;
			  biginteger r2 = 85;
			  auto co1 = dlog->exponentiate(g.get(), r);
			  auto h = dlog->exponentiate(g.get(), 17);

			  cout << "h: " << ((OpenSSLZpSafePrimeElement*)h.get())->getElementValue() << endl;
			  auto co2 = dlog->exponentiate(h.get(), r);
			  auto co3 = dlog->exponentiate(g.get(), r2);

			for (int i = 0; i < 2; i++) {
				  verifiers.push_back(make_shared<SigmaDlogVerifierComputation>(dlog, 40, get_seeded_prg()));
			}

			ZKFromSigmaVerifier verifier(channel, make_shared<SigmaANDVerifierComputation>(verifiers, 40), get_seeded_prg());

			vector<shared_ptr<SigmaProtocolMsg>> msgAs;
			vector<shared_ptr<SigmaProtocolMsg>> msgZs;

			for (int i = 0; i < 2; i++) {
				msgAs.push_back(make_shared<SigmaGroupElementMsg>(dlog->getIdentity()->generateSendableData()));
				msgZs.push_back(make_shared<SigmaBIMsg>());
			}

			auto msgA = make_shared<SigmaMultipleMsg>(msgAs);
			auto msgZ = make_shared<SigmaMultipleMsg>(msgZs);

			vector<shared_ptr<SigmaCommonInput>> inputs;

			inputs.push_back(make_shared<SigmaDlogCommonInput>(co1));
			inputs.push_back(make_shared<SigmaDlogCommonInput>(co2));

			cout << "g^r: " << ((OpenSSLZpSafePrimeElement*)co1.get())->getElementValue() << endl;
			cout << "h^r: " << ((OpenSSLZpSafePrimeElement*)co2.get())->getElementValue() << endl;
			cout << "g^85: " << ((OpenSSLZpSafePrimeElement*)co3.get())->getElementValue() << endl;

			shared_ptr<SigmaMultipleCommonInput> input = make_shared<SigmaMultipleCommonInput>(inputs);
			cout << "verified: " << verifier.verify(input.get(), msgA, msgZ) << endl;

			//Fiat Shamir stuff
			/*shared_ptr<CmtReceiver> receiver = make_shared<CmtPedersenReceiver>(channel, dlog);
			auto com = receiver->receiveCommitment();
			long id = 0;
			auto result = receiver->receiveDecommitment(id);
			if (result == NULL) {
				cout << "commitment failed" << endl;
			}
			else {
				cout << "the committed value is:" << result->toString() << endl;
			}

			shared_ptr<SigmaPedersenCmtKnowledgeVerifierComputation> verifierComputation = make_shared<SigmaPedersenCmtKnowledgeVerifierComputation>(dlog, 40, get_seeded_prg());
			ZKPOKFiatShamirFromSigmaVerifier verifier(channel, verifierComputation);

			cout << "before commitmentVal" << endl;

			auto commitmentVal = receiver->getCommitmentPhaseValues(id);

			cout << "commitmentVal: " << ((OpenSSLZpSafePrimeElement*)commitmentVal.get())->getElementValue() << endl;

			cout << "after commitmentVal" << endl;

			auto h = static_pointer_cast<GroupElement>(receiver->getPreProcessedValues()[0]);

			cout << "h: " << ((OpenSSLZpSafePrimeElement*)h.get())->getElementValue() << endl;

			cout << "after creation of h" << endl;
			auto commitment = static_pointer_cast<GroupElement>(commitmentVal);

			cout << "commitment: " << ((OpenSSLZpSafePrimeElement*)commitment.get())->getElementValue() << endl;

			cout << "after creation of commitment" << endl;
			SigmaPedersenCmtKnowledgeCommonInput commonInput(h, commitment);

			cout << "after creation of Pedersen common input" << endl;

			//biginteger r = 7;
			//auto co = dlog->exponentiate(g.get(), r);
			//shared_ptr<SigmaDlogCommonInput> commonInput = make_shared<SigmaDlogCommonInput>(co);
			vector<byte> cont;
			cout << "before Fiat Shamir input" << endl;
			auto input = make_shared<ZKPOKFiatShamirCommonInput>(&commonInput, cont);
			auto msgA = make_shared<SigmaGroupElementMsg>(dlog->getIdentity()->generateSendableData());
			auto msgZ = make_shared<SigmaBIMsg>();

			cout << "before output" << endl;
			bool output = verifier.verify(input.get(), msgA, msgZ);
			cout << "proof accepted: " << output << endl;*/

			//Pedersen commitment with proof
			/*CmtPedersenWithProofsReceiver receiver(channel, 40, dlog);
			auto com = receiver.receiveCommitment();
			long id = 0;
			auto result = receiver.receiveDecommitment(id);
			if (result == NULL) {
				cout << "commitment failed" << endl;
			}
			else {
				cout << "the committed value is:" << result->toString() << endl;
			}
			
			cout << "proof accepted: " << receiver.verifyKnowledge(id) << endl;*/
			//Commitment stuff
      /*
      shared_ptr<CmtReceiver> receiver = make_shared<CmtPedersenReceiver>(channel, dlog2);
			shared_ptr<CmtCommitter> committer = make_shared<CmtPedersenCommitter>(channel, dlog2);

			biginteger b = getRandomInRange(0, 1, get_seeded_prg().get());
			auto r2_com = make_shared<CmtBigIntegerCommitValue>(make_shared<biginteger>(b));
			//auto r2_com = committer->sampleRandomCommitValue();
      cout << "the committed value is:" << r2_com->toString() << endl;
      committer->commit(r2_com, 1);

			auto commitment = receiver->receiveCommitment();

      committer->decommit(1);

      auto result = receiver->receiveDecommitment(0);
      if (result == NULL) {
        cout << "commitment failed" << endl;
      } else {
        cout << "the committed value is:" << result->toString() << endl;
      }

			biginteger r1 = *((biginteger *)result->getX().get());
			biginteger r2 = *((biginteger *)r2_com->getX().get());
			biginteger r = r1^r2;
			cout << "r: " << r << endl;*/
    } catch (const logic_error& e) {
    		// Log error message in the exception object
    		cerr << e.what();
    }

    return 0;
}
