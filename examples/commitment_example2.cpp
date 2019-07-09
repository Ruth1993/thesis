#include "../../libscapi/include/comm/Comm.hpp"
#include "../../libscapi/include/interactive_mid_protocols/CommitmentScheme.hpp"
#include "../../libscapi/include//interactive_mid_protocols/CommitmentSchemePedersen.hpp"

int main(int argc, char* argv[]) {

    boost::asio::io_service io_service;
    SocketPartyData me, other;
    if (atoi(argv[1]) == 0){
            me = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8000);
            other = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8001);
    } else {
            me = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8001);
            other = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8000);
    }

    shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, me, other);


		// connect to party one
    channel->join(500, 5000);
    cout<<"channel established"<<endl;

		auto dlog = make_shared<OpenSSLDlogECF2m>("K-233");
		CmtPedersenCommitter committer(channel, dlog, get_seeded_prg());

		vector<byte> msg(10,0);
		auto val1 = committer.generateCommitValue(msg);

		committer.commit(val1, 2);

		committer.decommit(2);

		CmtPedersenReceiver receiver(channel, dlog, get_seeded_prg());

		auto output = receiver.receiveCommitment();

		auto val2 = receiver.receiveDecommitment(output.getCommitmentId());

		vector<byte> committedVector = receiver.generateBytesFromCommitValue(val2.get());

		for(int i=0; i<committedVector.size(); i++) {
			cout << committedVector[i];
		}
}
