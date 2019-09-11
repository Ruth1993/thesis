#include "../../libscapi/include/comm/Comm.hpp"
#include "../../libscapi/include/infra/Common.hpp"
#include "../../libscapi/include/interactive_mid_protocols/CommitmentScheme.hpp"
#include "../../libscapi/include/interactive_mid_protocols/CommitmentSchemePedersen.hpp"
#include "../../libscapi/include/mid_layer/OpenSSLSymmetricEnc.hpp"
#include "../../libscapi/include/primitives/DlogOpenSSL.hpp"
#include "../../libscapi/include/mid_layer/ElGamalEnc.hpp"
#include "../../libscapi/include/infra/Scanner.hpp"
#include "../../libscapi/include/infra/ConfigFile.hpp"
#include "../../libscapi/include/interactive_mid_protocols/SigmaProtocol.hpp"
#include "../../libscapi/include/interactive_mid_protocols/SigmaProtocolDlog.hpp"
#include "../../libscapi/include/interactive_mid_protocols/ZeroKnowledge.hpp"
#include "../../libscapi/include/interactive_mid_protocols/SigmaProtocolPedersenCommittedValue.hpp"
#include "../../libscapi/include/interactive_mid_protocols/SigmaProtocolPedersenCmtKnowledge.hpp"

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

    SocketPartyData p1 = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 7831);
    SocketPartyData p2 = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 7880);

    shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, p1, p2);

    //setup ElGamal communication
		//First read Dlog parameters from file dlog_params.txt
		ConfigFile cf("dlog_params.txt");
		string p_string = cf.Value("", "p");
		string g_string = cf.Value("", "g");
		string q_string = cf.Value("", "q");
    auto dlog = make_shared<OpenSSLDlogZpSafePrime>(q_string, g_string, p_string);
		auto g = dlog->getGenerator();
    ElGamalOnGroupElementEnc elgamal(dlog);
    auto pair = elgamal.generateKey();
    elgamal.setKey(pair.first, pair.second);

		shared_ptr<GroupElement> h = ((ElGamalPublicKey*) pair.first.get())->getH();
		cout << "h: " << ((OpenSSLZpSafePrimeElement *)h.get())->getElementValue() << endl;

		shared_ptr<GroupParams> group_params = dlog->getGroupParams();
		cout << ((ZpGroupParams*) group_params.get())->toString() << endl;

    try {
      channel->join(500, 5000);
      cout << "channel established" << endl;

      /*string longMessage = "Hi, this is a long message to test the writeWithSize approach";
      channel->writeWithSize(longMessage);


			//Send public key to party 2
      shared_ptr<KeySendableData> pk_sendable = ((ElGamalPublicKey*) pair.first.get())->generateSendableData();
			string pk_sendable_string = pk_sendable->toString();
      channel->writeWithSize(pk_sendable_string);

			//Receive [m] from party 2
			shared_ptr<AsymmetricCiphertextSendableData> c_m_sendable = make_shared<ElGamalOnGrElSendableData>(dlog->getGenerator()->generateSendableData(), dlog->getGenerator()->generateSendableData());
			vector<byte> raw_msg;
			channel->readWithSizeIntoVector(raw_msg);
			c_m_sendable->initFromByteVector(raw_msg);
			shared_ptr<AsymmetricCiphertext> c_m = elgamal.reconstructCiphertext(c_m_sendable.get());

			//Decrypt [m] and print on screen
			shared_ptr<Plaintext> p_m = elgamal.decrypt(c_m.get());
			cout << "m: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)p_m.get())->getElement()).get())->getElementValue() << endl;

			//Receive vec([[m]]) from party 2, decrypt and print on screen
			for(int i=0; i<2; i++) {
				shared_ptr<AsymmetricCiphertextSendableData> elem_sendable = make_shared<ElGamalOnGrElSendableData>(dlog->getGenerator()->generateSendableData(), dlog->getGenerator()->generateSendableData());
				vector<byte> raw_msg;
				channel->readWithSizeIntoVector(raw_msg);
				elem_sendable->initFromByteVector(raw_msg);
				shared_ptr<AsymmetricCiphertext> elem = elgamal.reconstructCiphertext(elem_sendable.get());

				shared_ptr<Plaintext> p_elem = elgamal.decrypt(elem.get());
				cout << "m: " << ((OpenSSLZpSafePrimeElement *)(((GroupElementPlaintext*)p_elem.get())->getElement()).get())->getElementValue() << endl;
			}*/

			//Zero-knowledge proof stuff
			/*auto dlog2 = make_shared<OpenSSLDlogECF2m>("K-233");
			ZKFromSigmaProver prover(channel, make_shared<SigmaDlogProverComputation>(dlog, 40));
			biginteger q = dlog->getOrder();
			biginteger r = getRandomInRange(0, q-1, get_seeded_prg().get());
			auto co = dlog->exponentiate(g.get(), r);
			shared_ptr<SigmaDlogProverInput> input = make_shared<SigmaDlogProverInput>(co, r);
			prover.prove(input);*/

			//Fiat Shamir stuff
			/*shared_ptr<SigmaPedersenCmtKnowledgeProverComputation> proverComputation = make_shared<SigmaPedersenCmtKnowledgeProverComputation>(dlog, 40, get_seeded_prg());
			ZKPOKFiatShamirFromSigmaProver prover(channel, proverComputation);

			shared_ptr<CmtCommitter> committer = make_shared<CmtPedersenCommitter>(channel, dlog);
			shared_ptr<CmtCommitValue> com = committer->sampleRandomCommitValue();
			cout << "the committed value is:" << com->toString() << endl;
			long id = 0;
			committer->commit(com, id);
			committer->decommit(id);

			cout << "before val" << endl;
			auto val = committer->getCommitmentPhaseValues(id);

			cout << "before h" << endl;

			auto h = static_pointer_cast<GroupElement>(committer->getPreProcessValues()[0]);
			cout << "h: " << ((OpenSSLZpSafePrimeElement*)h.get())->getElementValue() << endl;

			cout << "before commitment" << endl;
			auto commitment = static_pointer_cast<GroupElement>(val->getComputedCommitment());

			cout << "before x" << endl;
			biginteger x = *static_pointer_cast<biginteger>(val->getX()->getX());

			cout << "x: " << x << endl;

			cout << "before r" << endl;
			biginteger r = static_pointer_cast<BigIntegerRandomValue>(val->getR())->getR();

			cout << "r: " << r << endl;

			cout << "before Pedersen prover input" << endl;
			shared_ptr<SigmaPedersenCmtKnowledgeProverInput> proverInput = make_shared<SigmaPedersenCmtKnowledgeProverInput>(h, commitment, x, r);

			//biginteger q = dlog->getOrder();
			//biginteger k = 7;
			//auto r = dlog->exponentiate(g.get(), k);
			//shared_ptr<SigmaDlogProverInput> proverInput = make_shared<SigmaDlogProverInput>(r, k);

			vector<byte> cont;

			cout << "before FiatShamir prover input" << endl;
			auto input = make_shared<ZKPOKFiatShamirProverInput>(proverInput, cont);

			cout << "before actual proof" << endl;
			prover.prove(input);*/

			//Pedersen commitment with proof
		  CmtPedersenWithProofsCommitter committer(channel, 40, dlog);
		  shared_ptr<CmtCommitValue> com = committer.sampleRandomCommitValue();
		  cout << "the committed value is:" << com->toString() << endl;
		  long id = 0;
		  committer.commit(com, id);
		  committer.decommit(id);

		  committer.proveKnowledge(id);

		  biginteger a = 13;
		  biginteger b = 34;
		  biginteger c = a ^ b;
		  cout << "a xor b: " << c << endl;
    } catch (const logic_error& e) {
    		// Log error message in the exception object
    		cerr << e.what();
    }

	//Basic Coin Tossing protocol
/*auto dlog2 = make_shared<OpenSSLDlogECF2m>();
shared_ptr<CmtCommitter> committer = make_shared<CmtPedersenCommitter>(channel, dlog2);
shared_ptr<CmtReceiver> receiver = make_shared<CmtPedersenReceiver>(channel, dlog2);

biginteger b = getRandomInRange(0, 1, get_seeded_prg().get());
auto r1_com = make_shared<CmtBigIntegerCommitValue>(make_shared<biginteger>(b));
//auto r1_com = committer->sampleRandomCommitValue();
cout << "the committed value is:" << r1_com->toString() << endl;
auto commitment = receiver->receiveCommitment();

committer->commit(r1_com, 0);

auto result = receiver->receiveDecommitment(1);

committer->decommit(0);

if (result == NULL) {
	cout << "commitment failed" << endl;
} else {
	cout << "the committed value is:" << result->toString() << endl;
}

biginteger r2 = *((biginteger *)result->getX().get());
biginteger r1 = *((biginteger *)r1_com->getX().get());
biginteger r = r1^r2;
cout << "r: " << r << endl;*/

    return 0;
}
