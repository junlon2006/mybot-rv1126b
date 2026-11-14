/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_portal.h"
#include "check.h"

#include <arpa/inet.h>
#include <chrono>
#include <csignal>
#include <cstring>
#include <mutex>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace rv1126b_wifi;
namespace {
class Handler final : public PortalHandler {
  public:
    PortalStatus status() override {
        std::lock_guard<std::mutex> lock(mutex);
        return current;
    }
    std::vector<AccessPoint> networks() override {
        return {{"Wi-Fi \" <script>alert(1)</script>", -45, 3, 1}, {"测试网络", -60, 0, 6}};
    }
    std::vector<std::string> saved_networks() override {
        return {"home", "测试网络"};
    }
    bool submit(const std::string &ssid, const std::string &password, std::string &) override {
        std::lock_guard<std::mutex> lock(mutex);
        if (current.state == "connecting")
            return false;
        ++submissions;
        last_ssid = ssid;
        last_password = password;
        current = {"connecting", "", ssid, true, true};
        return true;
    }
    bool saved_action(const std::string &action, unsigned index, const std::string &expected_ssid,
                      std::string &) override {
        std::lock_guard<std::mutex> lock(mutex);
        last_action = action;
        last_index = index;
        const std::vector<std::string> saved{"home", "测试网络"};
        bool valid = index < saved.size() && saved[index] == expected_ssid;
        current.busy = valid;
        return valid;
    }
    bool finish(std::string &) override {
        std::lock_guard<std::mutex> lock(mutex);
        ++finishes;
        return true;
    }
    void complete(bool success) {
        std::lock_guard<std::mutex> lock(mutex);
        current.state = success ? "connected" : "error";
        current.busy = false;
    }
    std::mutex mutex;
    PortalStatus current{"ap", "", "", true, false};
    std::string last_ssid, last_password, last_action;
    unsigned submissions = 0, finishes = 0, last_index = 99;
};

unsigned short free_port(int type) {
    int fd = socket(AF_INET, type, 0);
    CHECK(fd >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
    socklen_t size = sizeof(address);
    CHECK(getsockname(fd, reinterpret_cast<sockaddr *>(&address), &size) == 0);
    unsigned short port = ntohs(address.sin_port);
    close(fd);
    return port;
}
int connect_to(unsigned short port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    timeval timeout{3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
    return fd;
}
std::string raw(unsigned short port, const std::string &request) {
    int fd = connect_to(port);
    size_t offset = 0;
    while (offset < request.size()) {
        ssize_t sent = send(fd, request.data() + offset, request.size() - offset, 0);
        if (sent <= 0)
            break;
        offset += static_cast<size_t>(sent);
    }
    shutdown(fd, SHUT_WR);
    std::string response;
    char buffer[4096];
    for (;;) {
        ssize_t got = recv(fd, buffer, sizeof(buffer), 0);
        if (got <= 0)
            break;
        response.append(buffer, static_cast<size_t>(got));
    }
    close(fd);
    return response;
}
std::string get(unsigned short port, const std::string &path) {
    return raw(port,
               "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(port) + "\r\n\r\n");
}
std::string post(unsigned short port, const std::string &token, const std::string &path,
                 const std::string &body, const std::string &origin = "") {
    std::string host = "127.0.0.1:" + std::to_string(port);
    return raw(port, "POST " + path + " HTTP/1.1\r\nHost: " + host +
                         "\r\nContent-Type: application/json\r\nX-CSRF-Token: " + token +
                         "\r\nOrigin: " + (origin.empty() ? "http://" + host : origin) +
                         "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body);
}
bool code(const std::string &response, unsigned expected) {
    return response.find("HTTP/1.1 " + std::to_string(expected) + " ") == 0;
}
std::vector<unsigned char> dns(unsigned short port, const std::vector<unsigned char> &query) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(sendto(fd, query.data(), query.size(), 0, reinterpret_cast<sockaddr *>(&address),
                 sizeof(address)) == static_cast<ssize_t>(query.size()));
    pollfd item{fd, POLLIN, 0};
    std::vector<unsigned char> response;
    if (poll(&item, 1, 150) > 0) {
        unsigned char buffer[1024];
        ssize_t got = recv(fd, buffer, sizeof(buffer), 0);
        if (got > 0)
            response.assign(buffer, buffer + got);
    }
    close(fd);
    return response;
}
} // namespace

int main() {
    signal(SIGPIPE, SIG_IGN);
    Handler handler;
    PortalConfig config{"127.0.0.1", free_port(SOCK_STREAM), free_port(SOCK_DGRAM)};
    auto portal = make_portal(config);
    std::string error;
    CHECK(portal->start(handler, error));
    CHECK(!portal->start(handler, error));

    std::string page = get(config.http_port, "/");
    CHECK(code(page, 200));
    CHECK(page.find("Content-Security-Policy:") != std::string::npos);
    CHECK(page.find("@TOKEN@") == std::string::npos);
    CHECK(page.find("textContent") != std::string::npos);
    CHECK(page.find("innerHTML") == std::string::npos);
    CHECK(page.find("setTimeout(leave,1000)") != std::string::npos);
    size_t start = page.find("const token='");
    CHECK(start != std::string::npos);
    std::string token = page.substr(start + strlen("const token='"), 64);
    CHECK(token.size() == 64);
    std::string scan = get(config.http_port, "/scan");
    CHECK(code(scan, 200));
    CHECK(scan.find("\"support_5g\":false") != std::string::npos);
    CHECK(scan.find("Wi-Fi \\\" <script>") != std::string::npos);
    CHECK(scan.find("测试网络") != std::string::npos);
    CHECK(get(config.http_port, "/saved/list").find("[\"home\",\"测试网络\"]") !=
          std::string::npos);
    CHECK(get(config.http_port, "/status").find("\"state\":\"ap\"") != std::string::npos);
    CHECK(get(config.http_port, "/status").find("\"busy\":false") != std::string::npos);
    for (const char *probe : {"/generate_204", "/hotspot-detect.html", "/connecttest.txt",
                              "/ncsi.txt", "/unknown", "/submit?ssid=leak&password=secret"}) {
        std::string response = get(config.http_port, probe);
        CHECK(code(response, 302));
        CHECK(response.find("Location: http://127.0.0.1:" + std::to_string(config.http_port) +
                            '/') != std::string::npos);
        CHECK(response.find("secret") == std::string::npos);
    }
    CHECK(code(get(config.http_port, "/submit"), 405));
    CHECK(code(get(config.http_port, "/exit"), 405));
    CHECK(code(post(config.http_port, "wrong", "/submit", "{}"), 403));
    CHECK(code(post(config.http_port, token, "/submit", "{}", "https://example.com"), 403));
    CHECK(code(
        raw(config.http_port, "POST /exit HTTP/1.1\r\nHost: attacker\r\nOrigin: http://attacker"
                              "\r\nX-CSRF-Token: " +
                                  token +
                                  "\r\nContent-Type: application/json\r\nContent-Length: "
                                  "2\r\n\r\n{}"),
        403));

    const std::string prefix =
        "POST /submit HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(config.http_port) + "\r\n";
    const std::string malformed[] = {
        "GET / HTTP/1.1\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n",
        "GET / HTTP/1.1\nHost: x\n\n",
        "GET / HTTP/1.1\r\n Host: x\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: x\r\n X: y\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: x\r\nContent-Length: +0\r\n\r\n",
        prefix + "Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
        prefix + "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        prefix + "Content-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
        prefix + "Content-Length: 1025\r\n\r\n",
        prefix + "Content-Length: 9\r\n\r\n{}",
        prefix + "\r\n{}",
        "GET / HTTP/1.1\r\nHost: x\r\nX: " + std::string(1100, 'x') + "\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n"};
    for (const auto &request : malformed)
        CHECK(code(raw(config.http_port, request), 400));
    CHECK(code(raw(config.http_port, "PUT / HTTP/1.1\r\nHost: x\r\n\r\n"), 405));

    const std::string invalid_json[] = {
        "{}",
        "[]",
        "{\"ssid\":\"a\",\"ssid\":\"b\",\"password\":\"12345678\"}",
        "{\"ssid\":\"a\",\"password\":\"short\"}",
        "{\"ssid\":\"a\",\"password\":\"12345678\",\"extra\":\"x\"}",
        "{\"ssid\":\"\\ud800\",\"password\":\"12345678\"}",
        "{\"ssid\":\"\\udc00\",\"password\":\"12345678\"}",
        "{\"ssid\":\"\\u0000\",\"password\":\"12345678\"}",
        "{\"ssid\":\"\\n\",\"password\":\"12345678\"}",
        "{\"ssid\":\"\xc0\xaf\",\"password\":\"12345678\"}",
        "{\"ssid\":\"\xed\xa0\x80\",\"password\":\"12345678\"}",
        "{\"ssid\":\"a\",\"password\":8}",
        "{\"ssid\":\"a\",\"password\":\"12345678\",}",
        "{\"ssid\":\"a\",\"password\":\"12345678\"}{}",
        "{\"ssid\":\"" + std::string(33, 'a') + "\",\"password\":\"12345678\"}",
        "{\"ssid\":\"a\",\"password\":\"" + std::string(64, 'z') + "\"}"};
    for (const auto &body : invalid_json)
        CHECK(code(post(config.http_port, token, "/submit", body), 400));
    {
        std::lock_guard<std::mutex> lock(handler.mutex);
        CHECK(handler.submissions == 0);
    }
    CHECK(code(post(config.http_port, token, "/submit",
                    "{\"ssid\":\"\\u6d4b\\u8bd5\\ud83d\\ude00\",\"password\":\"a\\\"b\\\\c123\"}"),
               202));
    {
        std::lock_guard<std::mutex> lock(handler.mutex);
        CHECK(handler.last_ssid == "测试😀");
        CHECK(handler.last_password == "a\"b\\c123");
        CHECK(handler.submissions == 1);
    }
    CHECK(get(config.http_port, "/status").find("\"state\":\"connecting\"") != std::string::npos);
    CHECK(get(config.http_port, "/status").find("\"busy\":true") != std::string::npos);
    CHECK(code(post(config.http_port, token, "/submit", "{\"ssid\":\"home\",\"password\":\"\"}"),
               409));
    handler.complete(false);
    CHECK(get(config.http_port, "/status").find("\"state\":\"error\"") != std::string::npos);
    CHECK(get(config.http_port, "/status").find("\"busy\":false") != std::string::npos);
    CHECK(code(post(config.http_port, token, "/submit", "{\"ssid\":\"home\",\"password\":\"\"}"),
               202));
    handler.complete(true);
    CHECK(get(config.http_port, "/status").find("\"state\":\"connected\"") != std::string::npos);
    CHECK(get(config.http_port, "/status").find("password") == std::string::npos);
    CHECK(
        code(post(config.http_port, token, "/saved/delete", "{\"index\":1,\"ssid\":\"测试网络\"}"),
             202));
    CHECK(get(config.http_port, "/status").find("\"busy\":true") != std::string::npos);
    handler.complete(true);
    CHECK(get(config.http_port, "/status").find("\"busy\":false") != std::string::npos);
    CHECK(
        code(post(config.http_port, token, "/saved/set_default", "{\"index\":0,\"ssid\":\"home\"}"),
             202));
    {
        std::lock_guard<std::mutex> lock(handler.mutex);
        CHECK(handler.last_action == "set_default");
        CHECK(handler.last_index == 0);
    }
    for (const char *body :
         {"{\"index\":\"0\",\"ssid\":\"home\"}", "{\"index\":-1,\"ssid\":\"home\"}",
          "{\"index\":01,\"ssid\":\"home\"}", "{\"index\":64,\"ssid\":\"home\"}",
          "{\"index\":999999,\"ssid\":\"home\"}", "{\"index\":0}", "{\"index\":0,\"ssid\":4}",
          "{\"index\":0,\"ssid\":\"\"}", "{\"index\":0,\"ssid\":\"\\u0000\"}", "{}"})
        CHECK(code(post(config.http_port, token, "/saved/delete", body), 400));
    CHECK(code(post(config.http_port, token, "/saved/delete", "{\"index\":2,\"ssid\":\"gone\"}"),
               409));
    CHECK(
        code(post(config.http_port, token, "/saved/delete", "{\"index\":0,\"ssid\":\"测试网络\"}"),
             409));
    CHECK(code(post(config.http_port, token, "/exit", "{\"index\":0}"), 400));
    CHECK(code(post(config.http_port, token, "/unknown", "{}"), 404));
    CHECK(code(post(config.http_port, token, "/exit", "{}"), 202));
    /* A subsequent HTTP request serializes after the finish callback. */
    CHECK(code(get(config.http_port, "/status"), 200));
    {
        std::lock_guard<std::mutex> lock(handler.mutex);
        CHECK(handler.finishes == 1);
    }

    std::vector<unsigned char> query{0x12, 0x34, 1,   0,   0,   1,   0,   0,   0,   0,
                                     0,    0,    7,   'e', 'x', 'a', 'm', 'p', 'l', 'e',
                                     3,    'c',  'o', 'm', 0,   0,   1,   0,   1};
    auto answer = dns(config.dns_port, query);
    CHECK(answer.size() == query.size() + 16);
    CHECK(answer[0] == 0x12 && answer[1] == 0x34 && answer[7] == 1);
    CHECK(answer[answer.size() - 4] == 127 && answer.back() == 1);
    auto aaaa = query;
    aaaa[aaaa.size() - 3] = 28;
    CHECK(dns(config.dns_port, aaaa).size() == query.size());
    auto edns = query;
    edns[11] = 1;
    edns.insert(edns.end(), {0, 0, 41, 4, 0, 0, 0, 0, 0, 0, 0});
    CHECK(dns(config.dns_port, edns).size() == query.size() + 16);
    std::vector<std::vector<unsigned char>> malformed_dns{{1, 2, 3},
                                                          std::vector<unsigned char>(600, 0)};
    auto bad = query;
    bad.pop_back();
    malformed_dns.push_back(bad);
    bad = query;
    bad[12] = 64;
    malformed_dns.push_back(bad);
    bad = query;
    bad[12] = 0xc0;
    bad[13] = 12; /* Self pointer. */
    malformed_dns.push_back(bad);
    bad[13] = 255; /* Out of bounds. */
    malformed_dns.push_back(bad);
    bad[13] = 0; /* Header pointer. */
    malformed_dns.push_back(bad);
    bad = query;
    bad[5] = 2;
    malformed_dns.push_back(bad);
    bad = query;
    bad[2] = 0x81;
    malformed_dns.push_back(bad);
    bad = query;
    bad.push_back(0);
    malformed_dns.push_back(bad);
    bad = edns;
    bad.back() = 100; /* Truncated OPT data. */
    malformed_dns.push_back(bad);
    for (const auto &packet : malformed_dns)
        CHECK(dns(config.dns_port, packet).empty());

    /* A client that never finishes its headers cannot hold shutdown hostage. */
    int slow = connect_to(config.http_port);
    CHECK(send(slow, "GET / HTTP/1.1\r\n", 16, 0) == 16);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    auto before = std::chrono::steady_clock::now();
    portal->stop();
    CHECK(std::chrono::steady_clock::now() - before < std::chrono::seconds(1));
    close(slow);
    portal->stop();
    CHECK(portal->start(handler, error));
    std::string new_page = get(config.http_port, "/");
    CHECK(code(new_page, 200));
    CHECK(new_page.find(token) == std::string::npos);
    portal->stop();
    PortalConfig invalid{"not-an-address", 8080, 8053};
    CHECK(!make_portal(invalid)->start(handler, error));
    puts("Wi-Fi AP portal HTTP/JSON/CSRF, asynchronous retry, captive DNS and bounded stop: PASS");
    return 0;
}
