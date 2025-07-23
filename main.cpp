#include <Poco/Net/DatagramSocket.h>
#include <Poco/Net/SocketAddress.h>
#include <Poco/Timespan.h>
#include <Poco/LRUCache.h>
#include <Poco/SharedPtr.h>
#include <Poco/Exception.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <thread>
#include <cstring>
#include <arpa/inet.h>
#include <set>

// Constants
const int MAX_RETRIES = 3;
const int MAX_RECURSION_DEPTH = 10;
const int DNS_PORT = 53;
const int TIMEOUT_MS = 2000;
const int CACHE_EXPIRY_SECONDS = 60;

// DNS Cache Entry
class DNSCacheEntry {
public:
    std::vector<std::string> ipAddresses;
    std::chrono::steady_clock::time_point timestamp;

    DNSCacheEntry(const std::vector<std::string>& ips)
        : ipAddresses(ips), timestamp(std::chrono::steady_clock::now()) {}

    bool isExpired(int seconds = CACHE_EXPIRY_SECONDS) const {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - timestamp).count() > seconds;
    }
};

Poco::LRUCache<std::string, DNSCacheEntry> dnsCache(100);

std::vector<uint8_t> buildDNSQuery(const std::string& hostname, uint16_t qtype = 1) {
    std::vector<uint8_t> query(512, 0);
    uint16_t transactionID = htons(0x1234);
    query[0] = transactionID >> 8;
    query[1] = transactionID & 0xff;
    query[2] = 0x01; // recursion desired
    query[5] = 0x01; // one question

    size_t pos = 12;
    size_t start = 0;
    while (true) {
        size_t end = hostname.find('.', start);
        std::string label = (end == std::string::npos) ? hostname.substr(start) : hostname.substr(start, end - start);
        query[pos++] = label.length();
        for (char c : label) query[pos++] = c;
        if (end == std::string::npos) break;
        start = end + 1;
    }

    query[pos++] = 0x00; // end of QNAME
    query[pos++] = (qtype >> 8); query[pos++] = (qtype & 0xff); // QTYPE
    query[pos++] = 0x00; query[pos++] = 0x01; // QCLASS IN
    query.resize(pos);
    return query;
}

std::vector<uint8_t> sendDNSQueryToServer(const std::vector<uint8_t>& query, const std::string& dnsServerIP) {
    Poco::Net::SocketAddress dnsServer(dnsServerIP, DNS_PORT);
    Poco::Net::DatagramSocket socket(Poco::Net::SocketAddress("0.0.0.0", 0), false);
    socket.setReceiveTimeout(Poco::Timespan(0, TIMEOUT_MS * 1000));

    for (int attempt = 1; attempt <= MAX_RETRIES; ++attempt) {
        try {
            socket.sendTo(query.data(), query.size(), dnsServer);
            std::vector<uint8_t> response(512);
            Poco::Net::SocketAddress sender;
            int len = socket.receiveFrom(response.data(), response.size(), sender);
            response.resize(len);
            return response;
        } catch (const Poco::TimeoutException&) {
            std::cerr << "[Timeout] Retry " << attempt << "/" << MAX_RETRIES << "\n";
        }
    }

    throw std::runtime_error("DNS query timed out after maximum retries.");
}

std::vector<std::string> parseDNSResponse(const std::vector<uint8_t>& response, uint16_t desiredType = 1, std::set<std::string>* nsServers = nullptr) {
    int qdCount = ntohs(*reinterpret_cast<const uint16_t*>(&response[4]));
    int anCount = ntohs(*reinterpret_cast<const uint16_t*>(&response[6]));
    int nsCount = ntohs(*reinterpret_cast<const uint16_t*>(&response[8]));
    size_t pos = 12;

    while (qdCount--) {
        while (response[pos] != 0) pos += response[pos] + 1;
        pos += 5;
    }

    std::vector<std::string> ipAddresses;

    for (int i = 0; i < anCount && pos < response.size(); ++i) {
        if ((response[pos] & 0xC0) == 0xC0) pos += 2;
        else while (response[pos] != 0) pos += response[pos] + 1, pos++;

        uint16_t type = ntohs(*reinterpret_cast<const uint16_t*>(&response[pos]));
        pos += 2;
        pos += 2; // class
        pos += 4; // TTL
        uint16_t dataLen = ntohs(*reinterpret_cast<const uint16_t*>(&response[pos]));
        pos += 2;

        if ((type == 1 && desiredType == 1) || (type == 28 && desiredType == 28)) {
            char buf[INET6_ADDRSTRLEN];
            if (type == 1 && dataLen == 4)
                inet_ntop(AF_INET, &response[pos], buf, INET_ADDRSTRLEN);
            else if (type == 28 && dataLen == 16)
                inet_ntop(AF_INET6, &response[pos], buf, INET6_ADDRSTRLEN);
            ipAddresses.emplace_back(buf);
        }

        pos += dataLen;
    }

    // Handle NS records
    if (nsServers && nsCount > 0) {
        for (int i = 0; i < nsCount && pos < response.size(); ++i) {
            if ((response[pos] & 0xC0) == 0xC0) pos += 2;
            else while (response[pos] != 0) pos += response[pos] + 1, pos++;

            uint16_t type = ntohs(*reinterpret_cast<const uint16_t*>(&response[pos]));
            pos += 2;
            pos += 2; // class
            pos += 4; // TTL
            uint16_t dataLen = ntohs(*reinterpret_cast<const uint16_t*>(&response[pos]));
            pos += 2;

            if (type == 2) { // NS record
                std::string ns;
                size_t nsEnd = pos + dataLen;
                while (pos < nsEnd && response[pos] != 0) {
                    int len = response[pos++];
                    ns += std::string(reinterpret_cast<const char*>(&response[pos]), len) + ".";
                    pos += len;
                }
                pos++; // skip null
                nsServers->insert(ns);
            } else {
                pos += dataLen;
            }
        }
    }

    return ipAddresses;
}

std::vector<std::string> resolveRecursively(const std::string& domain, const std::string& dnsServerIP, uint16_t qtype, int depth = 0) {
    if (depth > MAX_RECURSION_DEPTH)
        throw std::runtime_error("Maximum recursion depth exceeded.");

    auto query = buildDNSQuery(domain, qtype);
    std::set<std::string> nsServers;
    auto response = sendDNSQueryToServer(query, dnsServerIP);
    auto ips = parseDNSResponse(response, qtype, &nsServers);

    if (!ips.empty())
        return ips;

    for (const auto& ns : nsServers) {
        auto nsIps = resolveRecursively(ns, "8.8.8.8", 1, depth + 1);
        for (const auto& nsIp : nsIps) {
            try {
                auto retryQuery = buildDNSQuery(domain, qtype);
                auto retryResponse = sendDNSQueryToServer(retryQuery, nsIp);
                auto finalIps = parseDNSResponse(retryResponse, qtype);
                if (!finalIps.empty()) return finalIps;
            } catch (...) {}
        }
    }

    return {};
}

int main(int argc, char* argv[]) {
    std::vector<std::string> testDomains = (argc > 1) ?
        std::vector<std::string>(argv + 1, argv + argc) :
        std::vector<std::string>{"google.com", "openai.com", "wikipedia.org", "sub.example.co.uk", "google.com"};

    for (const auto& domain : testDomains) {
        std::cout << "\nResolving: " << domain << "\n";

        try {
            if (dnsCache.has(domain)) {
                DNSCacheEntry entry = *dnsCache.get(domain);
                if (!entry.isExpired()) {
                    std::cout << "[Cache Hit] IPs: ";
                    for (const auto& ip : entry.ipAddresses) std::cout << ip << " ";
                    std::cout << "\n";
                    continue;
                } else {
                    std::cout << "[Cache Expired] Re-querying DNS...\n";
                }
            } else {
                std::cout << "[Cache Miss] Performing recursive DNS query...\n";
            }

            std::vector<std::string> allIps;
            auto a_ips = resolveRecursively(domain, "8.8.8.8", 1);
            auto aaaa_ips = resolveRecursively(domain, "8.8.8.8", 28);

            allIps.insert(allIps.end(), a_ips.begin(), a_ips.end());
            allIps.insert(allIps.end(), aaaa_ips.begin(), aaaa_ips.end());

            if (!allIps.empty()) {
                dnsCache.add(domain, DNSCacheEntry(allIps));
                std::cout << "[Resolved] IPs: ";
                for (const auto& ip : allIps) std::cout << ip << " ";
                std::cout << "\n";
            } else {
                std::cout << "No IP addresses found.\n";
            }
        } catch (const std::exception& ex) {
            std::cerr << "[Error] " << ex.what() << "\n";
        }
    }

    return 0;
}

