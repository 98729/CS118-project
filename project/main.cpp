#include <iostream>
/* PLEASE include these headers */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <regex>
#include <filesystem>

#include <sys/stat.h>
#include <time.h>
#include <fstream>
#include <sstream>
#include <dirent.h>
#include <algorithm>
#include <ctime>
#include <chrono>
#include <unistd.h>
#include <thread>
#include <pthread.h>
#include <arpa/inet.h>
#include <list>
#include <unordered_map>
#include <map>
#include <string>
#include <bitset>

using namespace std;

#define MYPORT 5152
#define BACKLOG 10 /* pending connections queue size */

// struct iphdr {
//     unsigned int ihl : 4;
//     unsigned int version : 4;
//     u_int8_t tos;
//     u_int16_t tot_len;
//     u_int16_t id;
//     u_int16_t frag_off;
//     u_int8_t ttl;
//     u_int8_t protocol;
//     u_int16_t check;
//     u_int32_t saddr; // Source IP address
//     u_int32_t daddr; // Destination IP address
// };

// struct tcphdr
//   {
//     u_int16_t th_sport;                /* source port */
//     u_int16_t th_dport;                /* destination port */
//     tcp_seq th_seq;                /* sequence number */
//     tcp_seq th_ack;                /* acknowledgement number */
// #  if __BYTE_ORDER == __LITTLE_ENDIAN
//     u_int8_t th_x2:4;                /* (unused) */
//     u_int8_t th_off:4;                /* data offset */
// #  endif
// #  if __BYTE_ORDER == __BIG_ENDIAN
//     u_int8_t th_off:4;                /* data offset */
//     u_int8_t th_x2:4;                /* (unused) */
// #  endif
//     u_int8_t th_flags;
// #  define TH_FIN        0x01
// #  define TH_SYN        0x02
// #  define TH_RST        0x04
// #  define TH_PUSH        0x08
// #  define TH_ACK        0x10
// #  define TH_URG        0x20
//     u_int16_t th_win;                /* window */
//     u_int16_t th_sum;                /* checksum */
//     u_int16_t th_urp;                /* urgent pointer */
// };

// struct udphdr {
//     u_int16_t uh_sport;                /* source port */
//     u_int16_t uh_dport;                /* destination port */
//     u_int16_t uh_ulen;                /* udp length */
//     u_int16_t uh_sum;                /* udp checksum */
// };

// global vars
void *recvConnections(void *arg);
std::vector<int> fds;
int sockfd; /* listen on sockfd, new connection on new_fd */
// std::vector<std::string> lanLinks;
std::vector<std::string> clientIPs; /*0.0.0.0, 192...*/
map<string, int> map_addr_sock; // IP addr to socket_fd

size_t getSourcePort(std::vector<uint8_t> &pkt);
size_t getDestPort(std::vector<uint8_t> &pkt);
void updateSourcePort(std::string portNumber, iphdr *ipheader);
void updateDestinationPort(std::string portNumber, iphdr *ipheader);

std::string uint32ToIPv4(u_int32_t ip);
// NAT table
std::unordered_map<std::string, std::list<std::pair<std::string, std::string>>> myMap;
// ACL table (subnet, ports, subnet, ports)
std::vector<std::vector<std::string>> ACLMap;


int dynamic_port = 49152;

std::string szLanIp;
std::string szWanIp;

std::string uint32ToIPv4(u_int32_t ip)
{
    std::ostringstream oss;
    oss << ((ntohl(ip) >> 24) & 0xff) << "." // High byte of address
        << ((ntohl(ip) >> 16) & 0xff) << "."
        << ((ntohl(ip) >> 8) & 0xff) << "."
        << (ntohl(ip) & 0xff);

    return oss.str();
}

void printBufferAsHex(const unsigned char *buffer, int size)
{
  for (int i = 0; i < size; ++i)
  {
    int byte = static_cast<unsigned char>(buffer[i]);
    if (byte < 16)
      std::cout << '0';
    std::cout << std::hex << byte << ' ';
  }
  std::cout << std::dec << std::endl;
}


unsigned short compute_IPchecksum(std::vector<uint8_t> &pkt)
{
    auto incomingIpHdr = reinterpret_cast<iphdr *>(pkt.data());
    std::cout << "ip checksum (before): " << incomingIpHdr->check << std::endl;
    uint32_t sum = 0;
    for (uint32_t i = 0; i < (incomingIpHdr->ihl) * 4; i += 2)
    {
        auto headerword = reinterpret_cast<uint16_t *>(pkt.data() + i);
        auto temp1 = *headerword;
        auto temp2 = *headerword;
        auto temp3 = ((temp1 >> 8) & 0x00ff) + ((temp2 << 8) & 0xff00);
        sum += temp3;
        // std::cout << "temp1: " << (temp1 >> 8) << " temp2: " << ((temp2 << 8) & 0xff00) << std::endl;
        // std::cout << "headerword: " << temp3 << std::endl;
        // std::cout << "sum: " << sum << std::endl;
        // sum += (static_cast<uint16_t>(incomingIpHdr[i]) << 8) + incomingIpHdr[i+1];
    }
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // one's complement
    sum = ~sum;
    return sum;
}


unsigned short compute_TCPchecksum(std::vector<uint8_t> &pkt) {
    auto incomingIpHdr = reinterpret_cast<iphdr *>(pkt.data());
    auto hdrLen = static_cast<size_t>(incomingIpHdr->ihl) * 4;
    auto tcpHdr = reinterpret_cast<tcphdr *>(pkt.data() + hdrLen);
    std::cout << "tcp checksum (before): " << tcpHdr->th_sum << std::endl;
    uint32_t sum = 0;
    std::cout << "tcp header length: " <<incomingIpHdr->tot_len - hdrLen << std::endl;
    auto length1 = incomingIpHdr->tot_len;
    auto length2 = incomingIpHdr->tot_len;
    auto length3 = ((length1 >> 8) & 0x00ff) + ((length2 << 8) & 0xff00);
    std::cout << "real tcp header length: " << length3 - hdrLen << std::endl;
    for (uint32_t i = 0; i < length3 - hdrLen; i += 2)
    {
        auto headerword = reinterpret_cast<uint32_t *>(pkt.data() + hdrLen + i);
        auto temp1 = *headerword;
        auto temp2 = *headerword;
        auto temp3 = ((temp1 >> 8) & 0x00ff) + ((temp2 << 8) & 0xff00);
        sum += temp3;
        std::cout << "tcp temp3 header: " << temp3 << std::endl;
    }
    // add source and dest IP to checksum
    for (uint32_t i = 12; i < 20; i += 2)
    {
        auto headerword = reinterpret_cast<uint32_t *>(pkt.data() + i);
        auto temp1 = *headerword;
        auto temp2 = *headerword;
        auto temp3 = ((temp1 >> 8) & 0x00ff) + ((temp2 << 8) & 0xff00);
        sum += temp3;
        std::cout << "tcp temp3 IP: " << temp3 << std::endl;
    }
    // add protocol to checksum
    incomingIpHdr->protocol = IPPROTO_TCP;
    sum += (incomingIpHdr->protocol & 0x00ff);
    std::cout << "tcp temp3 proto: " << incomingIpHdr->protocol << std::endl;
    // std::cout << "protocol: " << (incomingIpHdr->protocol & 0x00ff) << std::endl;
    // add tcp length to checksum
    auto tmp1 = length3 - hdrLen;
    // auto tmp2 = length3 - hdrLen;
    // auto tmp3 = ((tmp1 >> 8) & 0x00ff) + ((tmp2 << 8) & 0xff00);
    // sum += tmp3;
    sum += tmp1;
    // std::cout << "tcp length temp1: " << tmp1 << std::endl;
    // std::cout << "tcp length temp2: " << tmp2 << std::endl;
    // std::cout << "tcp length temp3: " << tmp3 << std::endl;
    // std::cout << "length3: " << length3 << std::endl;
    // std::cout << "hdrlen: " << hdrLen << std::endl;
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // one's complement
    sum = ~sum;
    return sum;
}


unsigned short compute_UDPchecksum(std::vector<uint8_t> &pkt){
    auto incomingIpHdr = reinterpret_cast<iphdr *>(pkt.data());
    auto hdrLen = static_cast<size_t>(incomingIpHdr->ihl) * 4;
    auto udpHdr = reinterpret_cast<udphdr *>(pkt.data() + hdrLen);
    std::cout << "udp checksum (before): " << udpHdr->uh_sum << std::endl;
    uint32_t sum = 0;
    // std::cout << "udp header length1111: " << int(incomingIpHdr->tot_len) - hdrLen << std::endl;
    auto length1 = incomingIpHdr->tot_len;
    auto length2 = incomingIpHdr->tot_len;
    auto length3 = ((length1 >> 8) & 0x00ff) + ((length2 << 8) & 0xff00);
    std::cout << "real udp header length: " << length3 - hdrLen << std::endl;
    for (uint32_t i = 0; i < length3 - hdrLen; i += 2)
    {
        auto headerword = reinterpret_cast<uint32_t *>(pkt.data() + hdrLen + i);
        auto temp1 = *headerword;
        auto temp2 = *headerword;
        auto temp3 = ((temp1 >> 8) & 0x00ff) + ((temp2 << 8) & 0xff00);
        sum += temp3;
        std::cout << "udp header temp3: " << temp3 << std::endl;
    }
    // add source and dest IP to checksum
    for (uint32_t i = 12; i < 20; i += 2)
    {
        auto headerword = reinterpret_cast<uint32_t *>(pkt.data() + i);
        auto temp1 = *headerword;
        auto temp2 = *headerword;
        auto temp3 = ((temp1 >> 8) & 0x00ff) + ((temp2 << 8) & 0xff00);
        sum += temp3;
        std::cout << "IP temp3: " << temp3 << std::endl;
    }
    // add protocol to checksum
    sum += (incomingIpHdr->protocol & 0x00ff);
    // std::cout << "protocol: " << (incomingIpHdr->protocol & 0x00ff) << std::endl;
    // add udp length to checksum
    auto tmp1 = udpHdr->uh_ulen;
    auto tmp2 = udpHdr->uh_ulen;
    auto tmp3 = ((tmp1 >> 8) & 0x00ff) + ((tmp2 << 8) & 0xff00);
    sum += tmp3;
    // std::cout << "udp length temp3: " << tmp3 << std::endl;
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // one's complement
    sum = ~sum;
    return sum;
}


unsigned short updateIPChecksum(std::vector<uint8_t> &pkt)
{
    auto incomingIpHdr = reinterpret_cast<iphdr *>(pkt.data());
    std::cout << "ip checksum (before): " << incomingIpHdr->check << std::endl;
    incomingIpHdr->check = 0;
    uint32_t sum = 0;
    for (uint32_t i = 0; i < (incomingIpHdr->ihl) * 4; i += 2)
    {
        auto headerword = reinterpret_cast<uint16_t *>(pkt.data() + i);
        auto temp1 = *headerword;
        auto temp2 = *headerword;
        auto temp3 = ((temp1 >> 8) & 0x00ff) + ((temp2 << 8) & 0xff00);
        sum += temp3;
        // std::cout << "temp1: " << (temp1 >> 8) << " temp2: " << ((temp2 << 8) & 0xff00) << std::endl;
        // std::cout << "headerword: " << temp3 << std::endl;
        // std::cout << "sum: " << sum << std::endl;
        // sum += (static_cast<uint16_t>(incomingIpHdr[i]) << 8) + incomingIpHdr[i+1];
    }
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // one's complement
    sum = ~sum;
    auto temp1 = sum;
    auto temp2 = sum;
    incomingIpHdr->check = ((temp1 >> 8) & 0x00ff) + ((temp2 << 8) & 0xff00);
    // std::cout << "temp1: " << (temp1 >> 8) << " temp2: " << ((temp2 << 8) & 0xff00) << std::endl;
    // std::cout << "ip checksum (after): " << incomingIpHdr->check << std::endl;
    return incomingIpHdr->check;
}


void updateTransportChecksum(std::vector<uint8_t> &pkt)
{
    auto incomingIpHdr = reinterpret_cast<iphdr *>(pkt.data());
    auto hdrLen = static_cast<size_t>(incomingIpHdr->ihl) * 4;
    if (incomingIpHdr->protocol == IPPROTO_TCP)
    {
        auto tcpHdr = reinterpret_cast<tcphdr *>(pkt.data() + hdrLen);
        tcpHdr->th_sum = 0;
        unsigned short sum = compute_TCPchecksum(pkt);
        auto temp1 = sum;
        auto temp2 = sum;
        tcpHdr->th_sum = ((temp1 >> 8) & 0x00ff) + ((temp2 << 8) & 0xff00);
        std::cout << "tcp checksum (after): " << tcpHdr->th_sum << std::endl;
    }
    else {
        auto udpHdr = reinterpret_cast<udphdr *>(pkt.data() + hdrLen);
        udpHdr->uh_sum = 0;
        unsigned short sum = compute_UDPchecksum(pkt);
        auto temp1 = sum;
        auto temp2 = sum;
        udpHdr->uh_sum = ((temp1 >> 8) & 0x00ff) + ((temp2 << 8) & 0xff00);
        std::cout << "udp checksum (after): " << udpHdr->uh_sum << std::endl;
    }
}


// return true if IP is in this subnet
bool checkIP(u_int32_t IP, string subnet) {

    int idx = subnet.find("/");
    string nets = subnet.substr(0, idx);
    int length = std::stoi(subnet.substr(idx + 1));

    // convert uint32_t IP address to string with specific length
    uint32_t tempnet = inet_addr(nets.c_str());
    std::bitset<32> IPbits(IP);
    string ip = IPbits.to_string().substr(0, length);
    std::bitset<32> netbits(tempnet);
    string net = netbits.to_string().substr(0, length);


    for (int i = 0; i < length; i++) {
        if (ip.at(i) != net.at(i)){
            return false;
        }
    }
    return true;
}


// return true if port is in range
bool checkPort(u_int16_t port, string ports) {
    int idx = ports.find("-");
    int start = std::stoi(ports.substr(0, idx));
    int end = std::stoi(ports.substr(idx + 1));

    // convert uint16_t port number to int
    int portnum = static_cast<int>(port);
    if (portnum <= start && portnum >= end) {
        return false;
    }
    return true;
}


// return true if (saddr:sport->daddr:dport) is in the ACL range
bool checkACL(std::vector<uint8_t> &pkt) {
    auto incomingIpHdr = reinterpret_cast<iphdr *>(pkt.data());
    u_int32_t saddr = incomingIpHdr->saddr;
    u_int32_t daddr = incomingIpHdr->daddr;
    auto hdrLen = static_cast<size_t>(incomingIpHdr->ihl) * 4;
    u_int16_t sport;
    u_int16_t dport;
    if (incomingIpHdr->protocol == IPPROTO_TCP) {
        auto incomingTcpHdr = reinterpret_cast<tcphdr *>(pkt.data() + hdrLen);
        sport = incomingTcpHdr->th_sport;
        dport = incomingTcpHdr->th_dport;
    } else {
        auto incomingUdpHdr = reinterpret_cast<udphdr *>(pkt.data() + hdrLen);
        sport = incomingUdpHdr->uh_sport;
        dport = incomingUdpHdr->uh_dport;
    }

    for (std::size_t i = 0; i < ACLMap.size(); i++) {
        if ((checkIP(saddr, ACLMap[i][0]) && checkPort(sport, ACLMap[i][1]))
        || (checkIP(daddr, ACLMap[i][2]) && checkPort(dport, ACLMap[i][3]))) {
            return true;
        }
    }
    return false;
}


int main(int argc, char *argv[])
{

    std::string szLine;

    // First line is the router's LAN IP and the WAN IP
    std::getline(std::cin, szLine);
    size_t dwPos = szLine.find(' ');
    szLanIp = szLine.substr(0, dwPos);
    szWanIp = szLine.substr(dwPos + 1);

    std::cout << "Server's LAN IP: " << szLanIp << std::endl
              << "Server's WAN IP: " << szWanIp << std::endl;



    // Second line is always WAN port 0.0.0.0
    std::getline(std::cin, szLine);
    std::cout << "WAN port: " << szLine << std::endl;
    // auto wanLink = szLine;
    clientIPs.push_back(szLine);

    // The rest lines are LAN links
    std::string line;
    while (std::getline(std::cin, line))
    {
        if (line.empty())
        {
            // Empty line encountered, exit the loop
            break;
        }
        // Process the non-empty line
        // ...
        std::cout << "Host: " << line << std::endl;
        clientIPs.push_back(line);
    }


    std::cout << "" << std::endl;

    // Read NAT table, ended by empty line
    while (std::getline(std::cin, line))
    {
        if (line.empty())
        {
            // Empty line encountered, exit the loop
            break;
        }
        // Process the non-empty line
        // ...
        std::istringstream iss(line);
        std::string ipAddress, port1, port2;

        if (iss >> ipAddress >> port1 >> port2)
        {
            myMap[ipAddress].push_back(std::make_pair(port1, port2));
        }
    }


    // read ACL, ended by empty line
    while (std::getline(std::cin, line)) {
        if (line.empty())
        {
            // Empty line encountered, exit the loop
            break;
        }
        // Process the non-empty line
        // ...
        std::istringstream iss(line);
        std::string sIP, port1, dIP, port2;
        if (iss >> sIP >> port1 >> dIP >> port2)
        {
            std::vector<std::string> ACL;
            ACL.push_back(sIP);
            ACL.push_back(port1);
            ACL.push_back(dIP);
            ACL.push_back(port2);
            ACLMap.push_back(ACL);
        }
    }



    struct sockaddr_in my_addr; /* my address */
    // struct sockaddr_in their_addr; /* connector addr */

    /* create a socket */
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        cout << "Socket create failed" << endl;
        exit(1);
    }

    int reuse = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
        perror("Failed to set SO_REUSEADDR option");
        // handle the error
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0)
    {
        perror("Failed to set SO_REUSEPORT option");
        // handle the error
    }

    std::cout << "Successfully to create socket" << std::endl;

    // ...
    /* set the address info */
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(MYPORT); /* short, network byte order */
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    /* INADDR_ANY allows clients to connect to any one of the host’s IP
    address. Optionally, use this line if you know the IP to use:
    my_addr.sin_addr.s_addr = inet_addr(“127.0.0.1”);
    */
    memset(my_addr.sin_zero, '\0', sizeof(my_addr.sin_zero));

    /* bind the socket */
    if (::bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1)
    {
        cout << "bind failed" << endl;
        exit(1);
    }
    std::cout << "Bind successfully" << std::endl;
    // listen
    if (listen(sockfd, BACKLOG) == -1)
    {
        cout << "listen failed" << endl;
        exit(1);
    }
    std::cout << "Listen successfully" << std::endl;

    // std::vector<std::unique_ptr<std::thread>> threads;
    // while (1)
    // {

    //     int client_socket = accept(sockfd, (struct sockaddr *)&client_addr, (socklen_t *)&addr_len);
    //     if (client_socket < 0)
    //     {
    //         perror("accept failed");
    //         return -1;
    //     }
    //     // threads.emplace_back(std::make_unique<std::thread>(recvConnections, &client_socket));
    //     thread client_thread(recvConnections, &client_socket);
    //     client_thread.detach();

    // // accept WAN link
    // int wan_fd = accept(sockfd, (struct sockaddr*) &client_addr, (socklen_t *)&addr_len);
    // // std::cout << "wan fd: " << std::endl;

    // if (wan_fd == -1) {
    //     cout << "accept failed" << endl;
    //     return 0;
    // }
    // fds.push_back(wan_fd);

    // // loop to accept LAN link
    // for (std::size_t i = 0; i < lanLinks.size(); i++){
    //     int lan_fd = accept(sockfd, (struct sockaddr*) &client_addr, (socklen_t *)&addr_len);
    //     if (lan_fd == -1) {
    //         cout << "accept failed" << endl;
    //         return 0;
    //     }
    //     fds.push_back(lan_fd);
    // }
    // std::cout << "Accept successfully" << std::endl;

    // int i = 0;
    // std::vector<pthread_t> threads;
    while (1) {
        struct sockaddr_in client_addr;
        int addr_len = sizeof(client_addr);
        int client_fd = accept(sockfd, (struct sockaddr*) &client_addr, (socklen_t *)&addr_len);
        if (client_fd == -1) {
            cout << "accept failed" << endl;
            return 0;
        }
        thread client_thread(recvConnections, &client_fd);
        client_thread.detach();
        // if (pthread_create(&threads[i], nullptr, recvConnections, &client_fd) != 0) {
        //     throw std::runtime_error("ERROR: pthread_create failed.");
        // }
        // i++;
    }

    // for (pthread_t& thread : threads) {
    //     pthread_join(thread, nullptr);
    // }



    // // recv simultaneously
    // std::vector<pthread_t> threads(fds.size());
    // for (std::size_t i = 0; i < fds.size(); i++){
    //     int fd = fds[i];
    //     // std::cout << "fd: " << fd << std::endl;
    //     if (pthread_create(&threads[i], nullptr, recvConnections, &fd) != 0) {
    //         throw std::runtime_error("ERROR: pthread_create failed.");
    //     }
    // }
    // for (pthread_t& thread : threads) {
    //     pthread_join(thread, nullptr);
    // }


    // }

    // for (auto& thread : threads) {
    //     thread->join();
    // }

    // Close the server socket
    // close(sockfd);

    // // clean connection fds
    // for (int fd : fds) {
    //     // std::cout << "Close fd " << fd << std::endl;
    //     close(fd);
    // }
    // close(sockfd);

    // while (1)
    // {
    //     struct sockaddr_in client_address;
    //     socklen_t client_len = sizeof(client_address);

    //     int client_socket = accept(sockfd, (struct sockaddr *)&client_address, &client_len);
    //     if (client_socket < 0)
    //     {
    //         perror("accept failed");
    //         return -1;
    //     }
    //     // cout << "Connection accepted, spawning handler thread...\n" << endl;

    //     thread client_thread(recvConnections, client_socket);
    //     client_thread.detach();
    // }

    return 0;
}


int num_fd = 0;
// Function to recv client connections and send
void *recvConnections(void *arg)
{
    uint8_t buffer[2048];
    int fd = *(reinterpret_cast<int *>(arg));
    map_addr_sock[clientIPs[num_fd]] = fd;
    num_fd++;

    while (true)
    {
        auto recvSize = recv(fd, buffer, sizeof(buffer), 0);

        if (recvSize > 0)
        {
            std::cout << "receive size: " << recvSize << std::endl;
            std::cout << "fd: " << fd << std::endl;
            std::cout << "old buffer: " << std::endl;
            printBufferAsHex(buffer, recvSize);

            std::vector<uint8_t> pkt(buffer, buffer + recvSize);
            auto incomingIpHdr = reinterpret_cast<iphdr *>(pkt.data());
            // std::cout << "source addr: " << incomingIpHdr->saddr << std::endl;
            cout << "Connection from IP "
                 << ((ntohl(incomingIpHdr->saddr) >> 24) & 0xff) << "." // High byte of address
                 << ((ntohl(incomingIpHdr->saddr) >> 16) & 0xff) << "."
                 << ((ntohl(incomingIpHdr->saddr) >> 8) & 0xff) << "."
                 << (ntohl(incomingIpHdr->saddr) & 0xff) << ", port " // Low byte of addr
                                                                      //  << ntohs(incomingIpHdr->saddr.sin_port)
                 << endl;


            // total length
            auto totLen = static_cast<size_t>(ntohs(incomingIpHdr->tot_len));
            std::cout << "totalLen: " << totLen << std::endl;

            // header length
            auto hdrLen = static_cast<size_t>(incomingIpHdr->ihl) * 4;
            std::cout << "headerLen: " << hdrLen << std::endl;


            // check checksum, drop if checksum is wrong and restore addr_scoket map
            unsigned short checksum = compute_IPchecksum(pkt);
            if (checksum != 0) {
                cout << "Checksum failed. Dropping packet" << endl;
                // map_addr_sock[clientIPs[num_fd]] = 0;
                // num_fd--;
                continue;
            }

            // ttl (drop packet when ttl = 0, restore addr_scoket map)
            auto ttl = static_cast<size_t>(incomingIpHdr->ttl);
            std::cout << "ttl: " << ttl << std::endl;
            if (incomingIpHdr->ttl <= 1) {
                // map_addr_sock[clientIPs[num_fd]] = 0;
                // num_fd--;
                continue;
            }
            incomingIpHdr->ttl -= 1;

            // TODO: calculate checksum for TCP/UDP
            if (incomingIpHdr->protocol == IPPROTO_TCP)
            {
                std::cout << "This is a TCP packet" << std::endl;
                auto incomingTcpHdr = reinterpret_cast<tcphdr *>(pkt.data() + hdrLen);
                auto sourcePort = static_cast<size_t>(ntohs(incomingTcpHdr->th_sport));
                auto destPort = static_cast<size_t>(ntohs(incomingTcpHdr->th_dport));
                std::cout << "sourcePort: " << sourcePort << " destPort: " << destPort << std::endl;
                auto tcpHdrLen = static_cast<size_t>(incomingTcpHdr->th_off) * 4;
                std::cout << "payloadLen: " << totLen - hdrLen - tcpHdrLen << std::endl;
                std::cout << "from " << uint32ToIPv4(incomingIpHdr->saddr) << std::endl;
                std::cout << "send to " << uint32ToIPv4(incomingIpHdr->daddr) << std::endl;

                // TCP checksum check, restore addr_scoket map if drop packet
                unsigned short checksum = compute_TCPchecksum(pkt);
                if (checksum != 0){
                    cout << "Checksum failed. Dropping packet" << endl;
                    // map_addr_sock[clientIPs[num_fd]] = 0;
                    // num_fd--;
                    continue;
                } 
            }
            else if (incomingIpHdr->protocol == IPPROTO_UDP)
            {
                std::cout << "This is a UDP packet" << std::endl;
                auto incomingUdpHdr = reinterpret_cast<udphdr *>(pkt.data() + hdrLen);
                auto sourcePort = static_cast<size_t>(ntohs(incomingUdpHdr->uh_sport));
                auto destPort = static_cast<size_t>(ntohs(incomingUdpHdr->uh_dport));
                std::cout << "sourcePort: " << sourcePort << " destPort: " << destPort << std::endl;

                // UDP checksum check, restore addr_scoket map if drop packet
                unsigned short checksum = compute_UDPchecksum(pkt);
                if (checksum != 0){
                    cout << "Checksum failed. Dropping packet" << endl;
                    // map_addr_sock[clientIPs[num_fd]] = 0;
                    // num_fd--;
                    continue;
                }
            }



            // find destination address and do LAN to LAN forward
            bool found_lan = false;
            string str_des_ip = uint32ToIPv4(incomingIpHdr->daddr);
            string str_src_ip = uint32ToIPv4(incomingIpHdr->saddr);
            for (std::size_t i = 0; i < clientIPs.size(); i++) {
                if (uint32ToIPv4(incomingIpHdr->daddr) == clientIPs[i]) {
                    incomingIpHdr->check = updateIPChecksum(pkt);
                    std::cout << "checksum111111111: " << incomingIpHdr->check << std::endl;

                    if (checkACL(pkt)){
                        continue;
                    }
                    send(map_addr_sock[uint32ToIPv4(incomingIpHdr->daddr)], pkt.data(), recvSize, 0);
                    std::cout << "map " << map_addr_sock[uint32ToIPv4(incomingIpHdr->daddr)] << std::endl;
                    std::cout << "from " << uint32ToIPv4(incomingIpHdr->saddr) << std::endl;
                    std::cout << "send to " << uint32ToIPv4(incomingIpHdr->daddr) << std::endl;
                    int convertedValue = incomingIpHdr->ttl;
                    std::cout << "ttl after: " << convertedValue << endl;
                    printBufferAsHex(buffer, recvSize);
                    found_lan = true;
                    break;
                }
            }

            // static or dynamic send
            if (!found_lan) {
                // check destination is WAN link and rewrite
                if (str_des_ip == szWanIp) { // 98.149.235.132
                    // TODO check port to determine static or dynamic
                    auto port_num = getDestPort(pkt);
                    bool portExists = false;
                    for (const auto &entry : myMap) {
                        for (const auto &pair : entry.second) {
                            // static, rewrite dest, forward
                            if (pair.second == std::to_string(port_num)) {
                                portExists = true;
                                incomingIpHdr->daddr = inet_addr(entry.first.c_str());
                                updateDestinationPort(pair.first, incomingIpHdr);
                                for (std::size_t i = 0; i < clientIPs.size(); i++) {
                                    if (uint32ToIPv4(incomingIpHdr->daddr) == clientIPs[i]) {
                                        incomingIpHdr->check = updateIPChecksum(pkt);
                                        std::cout << "ma de"<< std::endl;
                                        updateTransportChecksum(pkt);
                                        // send from WAN to LAN
                                        std::cout << "map " << map_addr_sock[uint32ToIPv4(incomingIpHdr->daddr)] << std::endl;
                                        std::cout << "from " << uint32ToIPv4(incomingIpHdr->saddr) << std::endl;
                                        std::cout << "send to " << uint32ToIPv4(incomingIpHdr->daddr) << std::endl;\
                                        if (checkACL(pkt)){
                                            continue;
                                        }
                                        send(map_addr_sock[uint32ToIPv4(incomingIpHdr->daddr)], pkt.data(), recvSize, 0);
                                        break;
                                    }
                                }
                                break;
                            }
                        }
                        if (portExists) {
                            break;
                        }
                    }
                    if (!portExists) { // dynamic
                      // Dropped, as 49152 is not in the NAPT table yet.
                      // do nothing
                    }
                    // TODO rewrite dest ip according to NAPT table
                }
                else { // send to WAN
                    // rewrite port
                    auto port_num = getSourcePort(pkt);
                    bool portExists = false;
                    auto it = myMap.find(str_src_ip);
                    const std::list<std::pair<std::string, std::string>> &pairList = it->second;
                    for (const auto &pair : pairList) {
                        if (pair.first == std::to_string(port_num)) {
                            updateSourcePort(pair.second, incomingIpHdr);
                            // rewrite source ip address from LAN to WAN
                            cout << "string WAN IP: " << szWanIp << endl;
                            cout << "char WAN IP: " << szWanIp.c_str() << endl;
                            cout << "inet WAN IP: " << inet_addr(szWanIp.c_str()) << endl;
                            incomingIpHdr->saddr = inet_addr(szWanIp.c_str());
                            cout << "new source IP "
                                 << ((ntohl(incomingIpHdr->saddr) >> 24) & 0xff) << "." // High byte of address
                                 << ((ntohl(incomingIpHdr->saddr) >> 16) & 0xff) << "."
                                 << ((ntohl(incomingIpHdr->saddr) >> 8) & 0xff) << "."
                                 << (ntohl(incomingIpHdr->saddr) & 0xff) << ", port " // Low byte of addr
                                 // << ntohs(incomingIpHdr->saddr.sin_port)
                                 << endl;
                            incomingIpHdr->check = updateIPChecksum(pkt);
                            updateTransportChecksum(pkt);
                            std::cout << "map " << map_addr_sock[uint32ToIPv4(incomingIpHdr->daddr)] << std::endl;
                            std::cout << "from " << uint32ToIPv4(incomingIpHdr->saddr) << std::endl;
                            std::cout << "send to " << uint32ToIPv4(incomingIpHdr->daddr) << std::endl;
                            if (checkACL(pkt)){
                                continue;
                            }
                            send(map_addr_sock["0.0.0.0"], pkt.data(), recvSize, 0);
                            std::cout << "cao " << std::endl;
                            portExists = true;
                            break;
                        }
                    }

                    if (!portExists) { // allocate
                        // dynamic_port
                        myMap[str_src_ip].push_back(std::make_pair(std::to_string(port_num), std::to_string(dynamic_port)));
                        // rewrite source ip address e.g. 192. -> 98.
                        incomingIpHdr->saddr = inet_addr(szWanIp.c_str());
                        // rewrite port
                        updateSourcePort(std::to_string(dynamic_port), incomingIpHdr);
                        incomingIpHdr->check = updateIPChecksum(pkt);
                        updateTransportChecksum(pkt);
                        dynamic_port++;
                        send(map_addr_sock["0.0.0.0"], pkt.data(), recvSize, 0);
                    }
                }
            }

            // recvSize = recv(fd, buffer, sizeof(buffer), 0);
        }
    }

    // close in each thread
    close(fd);

    return 0;
}

void updateSourcePort(std::string portNumber, iphdr *ipheader)
{
    // Check the protocol
    if (ipheader->protocol == IPPROTO_UDP)
    {
        // UDP protocol
        udphdr *udpheader = reinterpret_cast<udphdr *>(reinterpret_cast<char *>(ipheader) + ipheader->ihl * 4);
        udpheader->uh_sport = htons(std::stoi(portNumber));
    }
    else if (ipheader->protocol == IPPROTO_TCP)
    {
        // TCP protocol
        tcphdr *tcpheader = reinterpret_cast<tcphdr *>(reinterpret_cast<char *>(ipheader) + ipheader->ihl * 4);
        tcpheader->th_sport = htons(std::stoi(portNumber));
    }
    else
    {
        // Unsupported protocol
        std::cout << "Unsupported protocol." << std::endl;
        return;
    }

    // Print the updated source port
    std::cout << "Updated source port: " << portNumber << std::endl;
}

void updateDestinationPort(std::string portNumber, iphdr *ipheader)
{
    // Check the protocol
    if (ipheader->protocol == IPPROTO_UDP)
    {
        // UDP protocol
        udphdr *udpheader = reinterpret_cast<udphdr *>(reinterpret_cast<char *>(ipheader) + ipheader->ihl * 4);
        udpheader->uh_dport = htons(std::stoi(portNumber));
    }
    else if (ipheader->protocol == IPPROTO_TCP)
    {
        // TCP protocol
        tcphdr *tcpheader = reinterpret_cast<tcphdr *>(reinterpret_cast<char *>(ipheader) + ipheader->ihl * 4);
        tcpheader->th_dport = htons(std::stoi(portNumber));
    }
    else
    {
        // Unsupported protocol
        std::cout << "Unsupported protocol." << std::endl;
        return;
    }

    // Print the updated destination port
    std::cout << "Updated destination port: " << portNumber << std::endl;
}

size_t getSourcePort(std::vector<uint8_t> &pkt)
{
    auto incomingIpHdr = reinterpret_cast<iphdr *>(pkt.data());
    // Check if the packet is UDP
    if (incomingIpHdr->protocol == IPPROTO_UDP)
    {
        struct udphdr *udpHeader = reinterpret_cast<struct udphdr *>(
            reinterpret_cast<char *>(incomingIpHdr) + incomingIpHdr->ihl * 4);
        return static_cast<size_t>(ntohs(udpHeader->uh_sport));
    }
    // Check if the packet is TCP
    else if (incomingIpHdr->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcpHeader = reinterpret_cast<struct tcphdr *>(
            reinterpret_cast<char *>(incomingIpHdr) + incomingIpHdr->ihl * 4);
        return static_cast<size_t>(ntohs(tcpHeader->th_sport));
    }
    // Handle other protocols or error cases
    else
    {
        // Return a default value or handle the case as needed
        return 0;
    }
}

size_t getDestPort(std::vector<uint8_t> &pkt)
{
    auto incomingIpHdr = reinterpret_cast<iphdr *>(pkt.data());
    // Check if the packet is UDP
    if (incomingIpHdr->protocol == IPPROTO_UDP)
    {
        struct udphdr *udpHeader = reinterpret_cast<struct udphdr *>(
            reinterpret_cast<char *>(incomingIpHdr) + incomingIpHdr->ihl * 4);
        return static_cast<size_t>(ntohs(udpHeader->uh_dport));
    }
    // Check if the packet is TCP
    else if (incomingIpHdr->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcpHeader = reinterpret_cast<struct tcphdr *>(
            reinterpret_cast<char *>(incomingIpHdr) + incomingIpHdr->ihl * 4);
        return static_cast<size_t>(ntohs(tcpHeader->th_dport));
    }
    // Handle other protocols or error cases
    else
    {
        // Return a default value or handle the case as needed
        return 0;
    }
}
