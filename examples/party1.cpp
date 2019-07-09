#include "../../libscapi/include/comm/Comm.hpp"
#include "../../libscapi/include/interactive_mid_protocols/CommitmentScheme.hpp"
#include "../../libscapi/include//interactive_mid_protocols/CommitmentSchemePedersen.hpp"

#include <boost/thread/thread.hpp>

int main(int argc, char* argv[]) {

    boost::asio::io_service io_service;

    SocketPartyData p1 = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8000);
    SocketPartyData p2 = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8001);

    shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, p1, p2);
    // connect to party one

    try {
      channel->join(500, 5000);
      cout<<"channel established"<<endl;

      auto dlog = make_shared<OpenSSLDlogECF2m>();
      shared_ptr<CmtCommitter> committer = make_shared<CmtPedersenCommitter>(channel, dlog);

      auto val = committer->sampleRandomCommitValue();
      cout << "the committed value is:" << val->toString() << endl;
      committer->commit(val, 0);
      committer->decommit(0);
    } catch (const logic_error& e) {
    		// Log error message in the exception object
    		cerr << e.what();
    }
}
