#include <libscapi/include/comm/Comm.hpp>

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
}
