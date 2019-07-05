//Committer
#include "../libscapi/include/comm/Comm.hpp"

shared_ptr<CmtCommitter> getCommitter(shared_ptr<CommParty> channel) {
  auto dlog = make_shared<OpenSSLDlogECF2m>();
  shared_ptr<CmtCommitter> committer = make_shared<CmtPedersenCommitter>(channel, dlog);

  return committer;
}

shared_ptr<CmtReceiver> getReceiver(shared_ptr<CommParty> channel) {
  auto dlog = make_shared<OpenSSLDlogECF2m>();
  shared_ptr<CmtReceiver> receiver = make_shared<CmtPedersenReceiver>(channel, dlog);

  return committer;
}

int main(int argc, char* argv[]) {
      boost::asio::io_service io_service;
      SocketPartyData sensor, server;
      if (atoi(argv[1]) == 0){
              sensor = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8000);
              server = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8001);
      } else {
              sensor = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8001);
              server = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8000);
      }

      shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, sensor, server);
      // connect to party one
      try {
        channel->join(500, 5000);
        cout<<"channel established"<<endl;
      }

}
