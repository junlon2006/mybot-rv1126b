/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_portal.h"
#include "portal_page.h"

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace rv1126b_wifi {
namespace {
using Clock = std::chrono::steady_clock;
constexpr size_t kHeaderLimit = 1024;
constexpr size_t kBodyLimit = 1024;

bool utf8(const std::string &value) {
    for (size_t i = 0; i < value.size();) {
        unsigned char c = static_cast<unsigned char>(value[i++]);
        if (c < 0x80)
            continue;
        unsigned count = c >= 0xc2 && c <= 0xdf   ? 1
                         : c >= 0xe0 && c <= 0xef ? 2
                         : c >= 0xf0 && c <= 0xf4 ? 3
                                                  : 0;
        if (!count || i + count > value.size())
            return false;
        uint32_t point = c & ((1u << (6 - count)) - 1);
        for (unsigned n = 0; n < count; ++n) {
            unsigned char next = static_cast<unsigned char>(value[i++]);
            if ((next & 0xc0) != 0x80)
                return false;
            point = (point << 6) | (next & 0x3f);
        }
        if ((count == 1 && point < 0x80) || (count == 2 && point < 0x800) ||
            (count == 3 && point < 0x10000) || point > 0x10ffff ||
            (point >= 0xd800 && point <= 0xdfff))
            return false;
    }
    return true;
}

std::string json_string(const std::string &value) {
    static const char hex[] = "0123456789abcdef";
    std::string out = "\"";
    bool valid = utf8(value);
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') {
            out += '\\';
            out += static_cast<char>(c);
        } else if (c < 0x20 || (!valid && c >= 0x80)) {
            if (c >= 0x80)
                out += "\\ufffd";
            else {
                out += "\\u00";
                out += hex[c >> 4];
                out += hex[c & 15];
            }
        } else
            out += static_cast<char>(c);
    }
    return out + '"';
}

struct JsonValue {
    std::string text;
    bool number = false;
};
class Json {
  public:
    explicit Json(const std::string &input) : input_(input) {
    }
    bool object(std::map<std::string, JsonValue> &out) {
        if (!utf8(input_) || !take('{'))
            return false;
        space();
        if (take('}'))
            return end();
        do {
            std::string key;
            JsonValue value;
            if (!string(key) || !take(':'))
                return false;
            space();
            if (pos_ < input_.size() && input_[pos_] == '"') {
                if (!string(value.text))
                    return false;
            } else {
                value.number = true;
                size_t start = pos_;
                while (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9')
                    ++pos_;
                value.text = input_.substr(start, pos_ - start);
                if (value.text.empty() || value.text.size() > 6 ||
                    (value.text.size() > 1 && value.text[0] == '0'))
                    return false;
            }
            if (!out.emplace(key, value).second)
                return false;
            if (take('}'))
                return end();
        } while (take(','));
        return false;
    }

  private:
    void space() {
        while (pos_ < input_.size() && (input_[pos_] == ' ' || input_[pos_] == '\n' ||
                                        input_[pos_] == '\r' || input_[pos_] == '\t'))
            ++pos_;
    }
    bool take(char c) {
        space();
        if (pos_ == input_.size() || input_[pos_] != c)
            return false;
        ++pos_;
        return true;
    }
    bool end() {
        space();
        return pos_ == input_.size();
    }
    bool hex4(uint32_t &out) {
        out = 0;
        for (int i = 0; i < 4; ++i) {
            if (pos_ == input_.size())
                return false;
            char c = input_[pos_++];
            int n = c >= '0' && c <= '9'   ? c - '0'
                    : c >= 'a' && c <= 'f' ? c - 'a' + 10
                    : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                           : -1;
            if (n < 0)
                return false;
            out = (out << 4) | static_cast<unsigned>(n);
        }
        return true;
    }
    static void append(std::string &out, uint32_t point) {
        if (point < 0x80)
            out += static_cast<char>(point);
        else if (point < 0x800) {
            out += static_cast<char>(0xc0 | (point >> 6));
            out += static_cast<char>(0x80 | (point & 63));
        } else if (point < 0x10000) {
            out += static_cast<char>(0xe0 | (point >> 12));
            out += static_cast<char>(0x80 | ((point >> 6) & 63));
            out += static_cast<char>(0x80 | (point & 63));
        } else {
            out += static_cast<char>(0xf0 | (point >> 18));
            out += static_cast<char>(0x80 | ((point >> 12) & 63));
            out += static_cast<char>(0x80 | ((point >> 6) & 63));
            out += static_cast<char>(0x80 | (point & 63));
        }
    }
    bool string(std::string &out) {
        if (!take('"'))
            return false;
        while (pos_ < input_.size()) {
            unsigned char c = static_cast<unsigned char>(input_[pos_++]);
            if (c == '"')
                return true;
            if (c < 0x20)
                return false;
            if (c != '\\') {
                out += static_cast<char>(c);
                continue;
            }
            if (pos_ == input_.size())
                return false;
            c = static_cast<unsigned char>(input_[pos_++]);
            if (c == '"' || c == '\\' || c == '/')
                out += static_cast<char>(c);
            else if (c == 'b')
                out += '\b';
            else if (c == 'f')
                out += '\f';
            else if (c == 'n')
                out += '\n';
            else if (c == 'r')
                out += '\r';
            else if (c == 't')
                out += '\t';
            else if (c == 'u') {
                uint32_t point;
                if (!hex4(point))
                    return false;
                if (point >= 0xd800 && point <= 0xdbff) {
                    if (pos_ + 2 > input_.size() || input_[pos_++] != '\\' || input_[pos_++] != 'u')
                        return false;
                    uint32_t low;
                    if (!hex4(low) || low < 0xdc00 || low > 0xdfff)
                        return false;
                    point = 0x10000 + ((point - 0xd800) << 10) + low - 0xdc00;
                } else if (point >= 0xdc00 && point <= 0xdfff)
                    return false;
                append(out, point);
            } else
                return false;
        }
        return false;
    }
    const std::string &input_;
    size_t pos_ = 0;
};

bool credential_text(const std::string &text) {
    return utf8(text) && std::none_of(text.begin(), text.end(),
                                      [](unsigned char c) { return c < 0x20 || c == 0x7f; });
}
bool credentials(const std::string &ssid, const std::string &password) {
    if (ssid.empty() || ssid.size() > 32 || !credential_text(ssid) || !credential_text(password))
        return false;
    if (password.empty() || (password.size() >= 8 && password.size() <= 63))
        return true;
    return password.size() == 64 &&
           std::all_of(password.begin(), password.end(), [](unsigned char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
           });
}

std::string lower(std::string value) {
    for (char &c : value)
        if (c >= 'A' && c <= 'Z')
            c += 'a' - 'A';
    return value;
}
std::string trim(const std::string &value) {
    size_t first = value.find_first_not_of(" \t");
    return first == std::string::npos
               ? ""
               : value.substr(first, value.find_last_not_of(" \t") - first + 1);
}
struct Request {
    std::string method, path, body;
    std::map<std::string, std::string> headers;
    size_t content_length = 0;
};
bool parse_headers(const std::string &header, Request &request) {
    size_t first = header.find("\r\n");
    if (first == std::string::npos)
        return false;
    std::string line = header.substr(0, first);
    size_t split = line.find(' '),
           second = line.find(' ', split == std::string::npos ? 0 : split + 1);
    if (split == std::string::npos || second == std::string::npos ||
        (line.substr(second + 1) != "HTTP/1.1" && line.substr(second + 1) != "HTTP/1.0"))
        return false;
    request.method = line.substr(0, split);
    request.path = line.substr(split + 1, second - split - 1);
    if (request.path.empty() || request.path[0] != '/' || request.path.size() > 256)
        return false;
    for (unsigned char c : request.path)
        if (c <= 0x20 || c >= 0x7f || c == '#')
            return false;
    for (size_t offset = first + 2; offset < header.size() - 2;) {
        size_t end = header.find("\r\n", offset), colon = header.find(':', offset);
        if (end == std::string::npos || colon == std::string::npos || colon >= end ||
            colon == offset)
            return false;
        std::string key = lower(header.substr(offset, colon - offset));
        for (unsigned char c : key)
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
                return false;
        std::string value = trim(header.substr(colon + 1, end - colon - 1));
        for (unsigned char c : value)
            if ((c < 0x20 && c != '\t') || c >= 0x7f)
                return false;
        if (!request.headers.emplace(key, value).second)
            return false;
        offset = end + 2;
    }
    if (request.headers.count("transfer-encoding") || !request.headers.count("host"))
        return false;
    auto length = request.headers.find("content-length");
    if (length != request.headers.end()) {
        if (length->second.empty() || length->second.size() > 4)
            return false;
        for (unsigned char c : length->second) {
            if (c < '0' || c > '9')
                return false;
            request.content_length = request.content_length * 10 + c - '0';
        }
    }
    return request.content_length <= kBodyLimit;
}

bool random_token(std::string &out) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    unsigned char data[32];
    size_t count = 0;
    while (count < sizeof(data)) {
        ssize_t got = read(fd, data + count, sizeof(data) - count);
        if (got <= 0) {
            if (got < 0 && errno == EINTR)
                continue;
            close(fd);
            return false;
        }
        count += static_cast<size_t>(got);
    }
    close(fd);
    static const char hex[] = "0123456789abcdef";
    out.clear();
    for (unsigned char c : data) {
        out += hex[c >> 4];
        out += hex[c & 15];
    }
    return true;
}

uint16_t word(const unsigned char *data) {
    return static_cast<uint16_t>((data[0] << 8) | data[1]);
}
void append_word(std::vector<unsigned char> &out, uint16_t value) {
    out.push_back(static_cast<unsigned char>(value >> 8));
    out.push_back(static_cast<unsigned char>(value));
}
/* Only a single, bounded question is accepted. Compression pointers must refer
 * backwards, stay in the name area and terminate within the DNS name limit. */
bool dns_name(const unsigned char *data, size_t size, size_t &offset) {
    size_t pos = offset, consumed = 0, expanded = 0;
    bool jumped = false;
    for (unsigned step = 0; step < 128; ++step) {
        if (pos >= size)
            return false;
        unsigned length = data[pos++];
        if (!jumped)
            ++consumed;
        if (!length) {
            offset += consumed;
            return expanded < 255;
        }
        if ((length & 0xc0) == 0xc0) {
            if (pos >= size)
                return false;
            size_t target = ((length & 63) << 8) | data[pos];
            if (target < 12 || target >= pos - 1)
                return false;
            if (!jumped)
                ++consumed;
            pos = target;
            jumped = true;
        } else {
            if (length > 63 || pos + length > size || expanded + length + 1 >= 255)
                return false;
            expanded += length + 1;
            pos += length;
            if (!jumped)
                consumed += length;
        }
    }
    return false;
}
std::vector<unsigned char> dns_response(const unsigned char *data, size_t size, in_addr address) {
    if (size < 12 || size > 512 || (data[2] & 0xfa) || word(data + 4) != 1 || word(data + 6) ||
        word(data + 8) || word(data + 10) > 1)
        return {};
    size_t end = 12;
    if (!dns_name(data, size, end) || end + 4 > size)
        return {};
    uint16_t type = word(data + end), klass = word(data + end + 2);
    end += 4;
    size_t complete = end;
    if (word(data + 10)) {
        if (!dns_name(data, size, complete) || complete + 10 > size || word(data + complete) != 41)
            return {};
        size_t extra = word(data + complete + 8);
        complete += 10;
        if (extra > size - complete)
            return {};
        complete += extra;
    }
    if (complete != size || klass != 1)
        return {};
    std::vector<unsigned char> out(data, data + end);
    out[2] = static_cast<unsigned char>(0x84 | (data[2] & 1));
    out[3] = 0;
    out[6] = 0;
    out[7] = type == 1 ? 1 : 0;
    out[10] = out[11] = 0;
    if (type == 1) {
        append_word(out, 0xc00c);
        append_word(out, 1);
        append_word(out, 1);
        append_word(out, 0);
        append_word(out, 0); /* No DNS caching when the portal closes. */
        append_word(out, 4);
        const auto *bytes = reinterpret_cast<const unsigned char *>(&address.s_addr);
        out.insert(out.end(), bytes, bytes + 4);
    }
    return out;
}

class SocketPortal final : public Portal {
  public:
    explicit SocketPortal(PortalConfig config) : config_(std::move(config)) {
    }
    ~SocketPortal() override {
        stop();
    }
    bool start(PortalHandler &handler, std::string &error) override {
        if (running_) {
            error = "Wi-Fi portal already running";
            return false;
        }
        if (inet_pton(AF_INET, config_.address.c_str(), &address_) != 1 || !config_.http_port ||
            !config_.dns_port || !random_token(token_)) {
            error = "Invalid Wi-Fi portal configuration";
            return false;
        }
        http_ = listener(SOCK_STREAM, config_.http_port);
        dns_ = listener(SOCK_DGRAM, config_.dns_port);
        if (http_ < 0 || dns_ < 0 || listen(http_, 8) != 0) {
            error = "Cannot bind Wi-Fi portal sockets";
            close_sockets();
            return false;
        }
        host_ = config_.address;
        if (config_.http_port != 80)
            host_ += ':' + std::to_string(config_.http_port);
        handler_ = &handler;
        running_ = true;
        try {
            http_thread_ = std::thread([this] { http_loop(); });
            dns_thread_ = std::thread([this] { dns_loop(); });
        } catch (...) {
            error = "Cannot start Wi-Fi portal workers";
            stop();
            return false;
        }
        return true;
    }
    void stop() override {
        running_ = false;
        {
            std::lock_guard<std::mutex> lock(client_mutex_);
            if (client_ >= 0)
                shutdown(client_, SHUT_RDWR);
        }
        if (http_thread_.joinable())
            http_thread_.join();
        if (dns_thread_.joinable())
            dns_thread_.join();
        close_sockets();
        handler_ = nullptr;
    }

  private:
    int listener(int type, unsigned short port) {
        int fd = socket(AF_INET, type, 0);
        if (fd < 0)
            return -1;
        int on = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        fcntl(fd, F_SETFD, FD_CLOEXEC);
        fcntl(fd, F_SETFL, O_NONBLOCK);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr = address_;
        address.sin_port = htons(port);
        if (bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
            close(fd);
            return -1;
        }
        return fd;
    }
    void close_sockets() {
        if (http_ >= 0)
            close(http_);
        if (dns_ >= 0)
            close(dns_);
        http_ = dns_ = -1;
    }
    bool ready(int fd, short events, Clock::time_point deadline) {
        while (running_ && Clock::now() < deadline) {
            pollfd item{fd, events, 0};
            int result = poll(&item, 1, 100);
            if (result > 0)
                return (item.revents & events) != 0;
            if (result < 0 && errno != EINTR)
                return false;
        }
        return false;
    }
    bool receive(int fd, Request &request) {
        std::string input;
        size_t header_size = 0;
        auto deadline = Clock::now() + std::chrono::seconds(2);
        while (ready(fd, POLLIN, deadline)) {
            char buffer[512];
            ssize_t count = recv(fd, buffer, sizeof(buffer), 0);
            if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
                continue;
            if (count <= 0)
                return false;
            input.append(buffer, static_cast<size_t>(count));
            if (!header_size) {
                size_t end = input.find("\r\n\r\n");
                if (end == std::string::npos) {
                    if (input.size() >= kHeaderLimit)
                        return false;
                    continue;
                }
                header_size = end + 4;
                if (header_size > kHeaderLimit || !parse_headers(input.substr(0, end + 2), request))
                    return false;
            }
            if (input.size() > header_size + request.content_length)
                return false;
            if (input.size() == header_size + request.content_length) {
                request.body = input.substr(header_size);
                return true;
            }
        }
        return false;
    }
    void respond(int fd, unsigned code, const std::string &body, const std::string &type,
                 const std::string &extra = "") {
        const char *reason = code == 200   ? "OK"
                             : code == 202 ? "Accepted"
                             : code == 302 ? "Found"
                             : code == 400 ? "Bad Request"
                             : code == 403 ? "Forbidden"
                             : code == 404 ? "Not Found"
                             : code == 405 ? "Method Not Allowed"
                             : code == 409 ? "Conflict"
                                           : "Error";
        std::string response =
            "HTTP/1.1 " + std::to_string(code) + ' ' + reason + "\r\nContent-Type: " + type +
            "\r\nContent-Length: " + std::to_string(body.size()) +
            "\r\nConnection: close\r\nCache-Control: no-store\r\n"
            "X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n" +
            extra + "\r\n" + body;
        auto deadline = Clock::now() + std::chrono::seconds(2);
        size_t offset = 0;
        while (offset < response.size() && ready(fd, POLLOUT, deadline)) {
#ifdef MSG_NOSIGNAL
            constexpr int flags = MSG_NOSIGNAL;
#else
            constexpr int flags = 0;
#endif
            ssize_t sent = send(fd, response.data() + offset, response.size() - offset, flags);
            if (sent < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
                continue;
            if (sent <= 0)
                break;
            offset += static_cast<size_t>(sent);
        }
    }
    void json(int fd, unsigned code, const std::string &body) {
        respond(fd, code, body, "application/json; charset=utf-8");
    }
    void reject(int fd, unsigned code) {
        json(fd, code, "{\"error\":\"request rejected\"}");
    }
    bool authorized(const Request &request) const {
        auto host = request.headers.find("host"), origin = request.headers.find("origin"),
             csrf = request.headers.find("x-csrf-token"),
             type = request.headers.find("content-type");
        if (host == request.headers.end() || origin == request.headers.end() ||
            csrf == request.headers.end() || type == request.headers.end())
            return false;
        bool host_ok = host->second == host_ ||
                       (config_.http_port == 80 && host->second == config_.address + ":80");
        std::string media = lower(trim(type->second.substr(0, type->second.find(';'))));
        return host_ok && origin->second == "http://" + host->second && csrf->second == token_ &&
               media == "application/json";
    }
    bool route(int fd, const Request &request) {
        if (request.method != "GET" && request.method != "POST") {
            reject(fd, 405);
            return false;
        }
        if (request.method == "GET") {
            if (request.content_length || !request.body.empty()) {
                reject(fd, 400);
                return false;
            }
            if (request.path == "/") {
                std::string page = kPortalPage;
                for (size_t pos = 0; (pos = page.find("@TOKEN@", pos)) != std::string::npos;) {
                    page.replace(pos, 7, token_);
                    pos += token_.size();
                }
                respond(fd, 200, page, "text/html; charset=utf-8",
                        "Content-Security-Policy: default-src 'none'; script-src 'nonce-" + token_ +
                            "'; style-src 'nonce-" + token_ +
                            "'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
                            "form-action 'none'\r\n");
            } else if (request.path == "/scan") {
                std::string body = "{\"support_5g\":false,\"aps\":[";
                auto aps = handler_->networks();
                for (size_t i = 0; i < aps.size() && i < 64; ++i) {
                    if (i)
                        body += ',';
                    body += "{\"ssid\":" + json_string(aps[i].ssid) +
                            ",\"rssi\":" + std::to_string(aps[i].rssi) +
                            ",\"authmode\":" + std::to_string(aps[i].authmode) + '}';
                }
                json(fd, 200, body + "]}");
            } else if (request.path == "/saved/list") {
                auto saved = handler_->saved_networks();
                std::string body = "[";
                for (size_t i = 0; i < saved.size() && i < 64; ++i) {
                    if (i)
                        body += ',';
                    body += json_string(saved[i]);
                }
                json(fd, 200, body + ']');
            } else if (request.path == "/status") {
                auto status = handler_->status();
                json(fd, 200,
                     "{\"state\":" + json_string(status.state) +
                         ",\"ssid\":" + json_string(status.ssid) +
                         ",\"concurrent\":" + (status.concurrent ? "true" : "false") +
                         ",\"busy\":" + (status.busy ? "true" : "false") + '}');
            } else if (request.path == "/submit" || request.path == "/exit" ||
                       request.path == "/saved/delete" || request.path == "/saved/set_default")
                reject(fd, 405);
            else
                respond(fd, 302, "", "text/plain", "Location: http://" + host_ + "/\r\n");
            return false;
        }
        if (!authorized(request)) {
            reject(fd, 403);
            return false;
        }
        std::map<std::string, JsonValue> fields;
        if (!Json(request.body).object(fields)) {
            reject(fd, 400);
            return false;
        }
        std::string error;
        if (request.path == "/submit") {
            if (fields.size() != 2 || !fields.count("ssid") || !fields.count("password") ||
                fields["ssid"].number || fields["password"].number ||
                !credentials(fields["ssid"].text, fields["password"].text)) {
                reject(fd, 400);
                return false;
            }
            if (!handler_->submit(fields["ssid"].text, fields["password"].text, error))
                reject(fd, 409);
            else
                json(fd, 202, "{\"status\":\"pending\"}");
        } else if (request.path == "/saved/delete" || request.path == "/saved/set_default") {
            if (fields.size() != 2 || !fields.count("index") || !fields["index"].number ||
                !fields.count("ssid") || fields["ssid"].number || fields["ssid"].text.empty() ||
                fields["ssid"].text.size() > 32 || !credential_text(fields["ssid"].text)) {
                reject(fd, 400);
                return false;
            }
            unsigned index = static_cast<unsigned>(std::stoul(fields["index"].text));
            if (index >= 64) {
                reject(fd, 400);
                return false;
            }
            if (!handler_->saved_action(request.path.substr(7), index, fields["ssid"].text, error))
                reject(fd, 409);
            else
                json(fd, 202, "{\"status\":\"pending\"}");
        } else if (request.path == "/exit") {
            if (!fields.empty()) {
                reject(fd, 400);
                return false;
            }
            json(fd, 202, "{\"status\":\"pending\"}");
            return true;
        } else
            reject(fd, 404);
        return false;
    }
    void http_loop() {
        while (running_) {
            if (!ready(http_, POLLIN, Clock::now() + std::chrono::milliseconds(200)))
                continue;
            int fd = accept(http_, nullptr, nullptr);
            if (fd < 0)
                continue;
            fcntl(fd, F_SETFD, FD_CLOEXEC);
            fcntl(fd, F_SETFL, O_NONBLOCK);
#ifdef SO_NOSIGPIPE
            int on = 1;
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
            {
                std::lock_guard<std::mutex> lock(client_mutex_);
                client_ = fd;
            }
            bool finish = false;
            try {
                Request request;
                if (receive(fd, request))
                    finish = route(fd, request);
                else if (running_)
                    reject(fd, 400);
            } catch (...) {
                /* Keep unexpected backend failures out of HTTP responses. */
                if (running_)
                    reject(fd, 409);
            }
            {
                std::lock_guard<std::mutex> lock(client_mutex_);
                close(fd);
                client_ = -1;
            }
            if (finish && running_) {
                std::string error;
                try {
                    handler_->finish(error);
                } catch (...) {
                }
            }
        }
    }
    void dns_loop() {
        while (running_) {
            if (!ready(dns_, POLLIN, Clock::now() + std::chrono::milliseconds(200)))
                continue;
            unsigned char data[513];
            sockaddr_in peer{};
            socklen_t length = sizeof(peer);
            ssize_t count =
                recvfrom(dns_, data, sizeof(data), 0, reinterpret_cast<sockaddr *>(&peer), &length);
            if (count <= 0)
                continue;
            auto response = dns_response(data, static_cast<size_t>(count), address_);
            if (!response.empty())
                sendto(dns_, response.data(), response.size(), 0,
                       reinterpret_cast<sockaddr *>(&peer), length);
        }
    }
    PortalConfig config_;
    in_addr address_{};
    std::string host_, token_;
    PortalHandler *handler_ = nullptr;
    std::atomic<bool> running_{false};
    int http_ = -1, dns_ = -1, client_ = -1;
    std::mutex client_mutex_;
    std::thread http_thread_, dns_thread_;
};
} // namespace
std::unique_ptr<Portal> make_portal(const PortalConfig &config) {
    return std::make_unique<SocketPortal>(config);
}
} // namespace rv1126b_wifi
