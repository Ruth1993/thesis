#include "../../libscapi/include/comm/Comm.hpp"
#include "../../libscapi/include/interactive_mid_protocols/CommitmentScheme.hpp"
#include "../../libscapi/include//interactive_mid_protocols/CommitmentSchemePedersen.hpp"

#include <boost/thread/thread.hpp>

int main(int argc, char* argv[]) {

    boost::asio::io_service io_service;

    SocketPartyData p2 = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8001);
    SocketPartyData p1 = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8000);

    shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, p2, p1);
    // connect to party one

    try {
      channel->join(500, 5000);
      cout<<"channel established"<<endl;

      auto dlog = make_shared<OpenSSLDlogECF2m>();
      shared_ptr<CmtReceiver> receiver = make_shared<CmtPedersenReceiver>(channel, dlog);

      auto commitment = receiver->receiveCommitment();
      auto result = receiver->receiveDecommitment(0);
      if (result == NULL) {
        cout << "commitment failed" << endl;
      } else {
        cout << "the committed value is:" << result->toString() << endl;
      }
    } catch (const logic_error& e) {
    		// Log error message in the exception object
    		cerr << e.what();
    }
}
