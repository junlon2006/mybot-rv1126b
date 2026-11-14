/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_backend_internal.h"

#include <openssl/evp.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <openssl/crypto.h>
#include <cctype>
#include <cstdlib>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <algorithm>
#include <chrono>
#include <climits>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <thread>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

extern char **environ;

namespace rv1126b_wifi {
namespace {
using Clock = std::chrono::steady_clock;
constexpr size_t kMaxOutput = 1024 * 1024;
constexpr unsigned kCommandTimeout = 3000;
constexpr const char *kCredentialFile = "wifi.credentials";

[[maybe_unused]] bool private_directory(const std::string &path, int &fd, std::string &error) {
    if (path.empty() || (mkdir(path.c_str(), 0700) != 0 && errno != EEXIST)) {
        error = "Cannot create private Wi-Fi directory";
        return false;
    }
    fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    struct stat st {};
    if (fd < 0 || fstat(fd, &st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 0077)) {
        if (fd >= 0)
            close(fd);
        fd = -1;
        error = "Wi-Fi directory must be owned by the current user with mode 0700";
        return false;
    }
    return true;
}

bool write_all(int fd, const std::string &contents) {
    size_t offset = 0;
    while (offset < contents.size()) {
        ssize_t size = write(fd, contents.data() + offset, contents.size() - offset);
        if (size < 0 && errno == EINTR)
            continue;
        if (size <= 0)
            return false;
        offset += static_cast<size_t>(size);
    }
    return true;
}

bool atomic_private_file(int directory, const std::string &name, const std::string &contents,
                         std::string &error) {
    struct stat existing {};
    if (fstatat(directory, name.c_str(), &existing, AT_SYMLINK_NOFOLLOW) == 0 &&
        (!S_ISREG(existing.st_mode) || existing.st_uid != geteuid())) {
        error = "Refusing unsafe Wi-Fi state file";
        return false;
    }
    std::string temporary = name + ".new-" + std::to_string(getpid());
    int fd = openat(directory, temporary.c_str(),
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        error = "Cannot create private Wi-Fi state file";
        return false;
    }
    bool ok = write_all(fd, contents) && fsync(fd) == 0;
    if (close(fd) != 0)
        ok = false;
    if (ok)
        ok = renameat(directory, temporary.c_str(), directory, name.c_str()) == 0;
    if (!ok) {
        unlinkat(directory, temporary.c_str(), 0);
        error = "Cannot atomically save Wi-Fi state";
        return false;
    }
    if (fsync(directory) != 0) {
        error = "Cannot synchronize Wi-Fi state directory";
        return false;
    }
    return true;
}

bool read_private_file(int directory, const std::string &name, std::string &contents,
                       std::string &error, bool missing_ok) {
    int fd = openat(directory, name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT && missing_ok) {
        contents.clear();
        return true;
    }
    struct stat st {};
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 0077) || st.st_size < 0 || st.st_size > 16384) {
        if (fd >= 0)
            close(fd);
        error = "Cannot read private Wi-Fi credentials (regular owned file, mode 0600 required)";
        return false;
    }
    contents.clear();
    char buffer[2048];
    for (;;) {
        ssize_t size = read(fd, buffer, sizeof(buffer));
        if (size < 0 && errno == EINTR)
            continue;
        if (size < 0 || contents.size() + static_cast<size_t>(size) > 16384) {
            close(fd);
            error = "Cannot read Wi-Fi state";
            return false;
        }
        if (!size)
            break;
        contents.append(buffer, static_cast<size_t>(size));
    }
    close(fd);
    return true;
}

bool hex_psk(const std::string &psk) {
    return psk.size() == 64 &&
           std::all_of(psk.begin(), psk.end(), [](unsigned char c) { return std::isxdigit(c); });
}

class Child {
  public:
    Child() = default;
    Child(const Child &) = delete;
    Child &operator=(const Child &) = delete;
    ~Child() {
        stop();
    }
    bool start(const std::vector<std::string> &arguments, int output, std::string &error,
               const std::map<std::string, std::string> &environment = {}) {
        if (pid_ > 0 || arguments.empty()) {
            error = "Invalid Wi-Fi process state";
            return false;
        }
        std::vector<char *> argv;
        for (const auto &argument : arguments)
            argv.push_back(const_cast<char *>(argument.c_str()));
        argv.push_back(nullptr);
        std::vector<std::string> variables;
        for (char **entry = environ; *entry; ++entry) {
            std::string item = *entry;
            if (!environment.count(item.substr(0, item.find('='))))
                variables.push_back(std::move(item));
        }
        for (const auto &entry : environment)
            variables.push_back(entry.first + "=" + entry.second);
        std::vector<char *> envp;
        for (auto &entry : variables)
            envp.push_back(const_cast<char *>(entry.c_str()));
        envp.push_back(nullptr);
        posix_spawn_file_actions_t actions;
        posix_spawnattr_t attributes;
        posix_spawn_file_actions_init(&actions);
        posix_spawnattr_init(&attributes);
        posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
        posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
        if (output >= 0)
            posix_spawn_file_actions_adddup2(&actions, output, STDOUT_FILENO);
        else
            posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
        sigset_t empty, defaults;
        sigemptyset(&empty);
        sigemptyset(&defaults);
        sigaddset(&defaults, SIGTERM);
        sigaddset(&defaults, SIGINT);
        sigaddset(&defaults, SIGPIPE);
        posix_spawnattr_setsigmask(&attributes, &empty);
        posix_spawnattr_setsigdefault(&attributes, &defaults);
        posix_spawnattr_setpgroup(&attributes, 0);
        posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK |
                                                  POSIX_SPAWN_SETSIGDEF);
        int result = posix_spawn(&pid_, argv[0], &actions, &attributes, argv.data(), envp.data());
        posix_spawn_file_actions_destroy(&actions);
        posix_spawnattr_destroy(&attributes);
        if (result != 0) {
            pid_ = -1;
            error = "Cannot execute Wi-Fi helper: " + arguments[0];
            return false;
        }
        return true;
    }
    bool running() {
        if (pid_ <= 0)
            return false;
        int status = 0;
        pid_t result = waitpid(pid_, &status, WNOHANG);
        if (result == 0 || (result < 0 && errno == EINTR))
            return true;
        status_ = result > 0 ? status : -1;
        pid_ = -1;
        return false;
    }
    bool succeeded() const {
        return status_ >= 0 && WIFEXITED(status_) && !WEXITSTATUS(status_);
    }
    void stop() {
        if (!running())
            return;
        kill(-pid_, SIGTERM);
        auto end = Clock::now() + std::chrono::milliseconds(400);
        while (running() && Clock::now() < end)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (pid_ > 0) {
            kill(-pid_, SIGKILL);
            int status = 0;
            while (waitpid(pid_, &status, 0) < 0 && errno == EINTR) {
            }
            pid_ = -1;
            status_ = status;
        }
    }

  private:
    pid_t pid_ = -1;
    int status_ = -1;
};

[[maybe_unused]] std::string find_program(const std::string &program) {
    /* Fixed system paths avoid shell lookup and accidental local executables. */
    for (const char *directory : {"/usr/sbin/", "/sbin/", "/usr/bin/", "/bin/"}) {
        std::string path = std::string(directory) + program;
        struct stat st {};
        if (stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode) && access(path.c_str(), X_OK) == 0)
            return path;
    }
    return {};
}

[[maybe_unused]] std::string read_text(const std::string &path) {
    std::ifstream input(path);
    std::ostringstream value;
    if (input)
        value << input.rdbuf();
    return value.str();
}

class Control {
  public:
    ~Control() {
        close_socket();
    }
    void close_socket() {
        if (fd_ >= 0)
            close(fd_);
        fd_ = -1;
        if (!local_.empty())
            unlink(local_.c_str());
        local_.clear();
    }
    bool open_socket(const std::string &remote, const std::string &local) {
        close_socket();
        if (remote.size() >= sizeof(sockaddr_un::sun_path) ||
            local.size() >= sizeof(sockaddr_un::sun_path))
            return false;
        fd_ = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (fd_ < 0)
            return false;
        fcntl(fd_, F_SETFD, FD_CLOEXEC);
        fcntl(fd_, F_SETFL, O_NONBLOCK);
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        std::memcpy(address.sun_path, local.c_str(), local.size() + 1);
        if (bind(fd_, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
            close_socket();
            return false;
        }
        local_ = local;
        std::memset(address.sun_path, 0, sizeof(address.sun_path));
        std::memcpy(address.sun_path, remote.c_str(), remote.size() + 1);
        if (::connect(fd_, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
            close_socket();
            return false;
        }
        return true;
    }
    std::string request(const std::string &command, unsigned timeout = 1000) {
        if (fd_ < 0)
            return {};
        char buffer[65536];
        /* Discard late replies/events before issuing another command. */
        while (recv(fd_, buffer, sizeof(buffer), MSG_DONTWAIT) > 0) {
        }
        if (send(fd_, command.data(), command.size(), 0) != static_cast<ssize_t>(command.size()))
            return {};
        auto end = Clock::now() + std::chrono::milliseconds(timeout);
        while (Clock::now() < end) {
            auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(end - Clock::now());
            pollfd wait{fd_, POLLIN, 0};
            int result = poll(&wait, 1, static_cast<int>(remaining.count()));
            if (result < 0 && errno == EINTR)
                continue;
            if (result <= 0 || !(wait.revents & POLLIN))
                return {};
            ssize_t size = recv(fd_, buffer, sizeof(buffer), 0);
            if (size > 0 && buffer[0] != '<')
                return std::string(buffer, static_cast<size_t>(size));
        }
        return {};
    }
    bool ok(const std::string &command) {
        return request(command, 200).rfind("OK", 0) == 0;
    }

  private:
    int fd_ = -1;
    std::string local_;
};

std::map<std::string, std::string> fields(const std::string &text) {
    std::map<std::string, std::string> result;
    std::istringstream input(text);
    std::string line;
    while (std::getline(input, line)) {
        size_t equal = line.find('=');
        if (equal != std::string::npos)
            result[line.substr(0, equal)] = line.substr(equal + 1);
    }
    return result;
}

bool process_uses_interface(const std::string &program, const std::string &interface) {
    DIR *directory = opendir("/proc");
    if (!directory)
        return true; /* Cannot establish exclusive ownership. */
    bool conflict = false;
    while (dirent *entry = readdir(directory)) {
        if (!std::all_of(entry->d_name, entry->d_name + std::strlen(entry->d_name),
                         [](unsigned char c) { return std::isdigit(c); }))
            continue;
        std::ifstream file(std::string("/proc/") + entry->d_name + "/cmdline", std::ios::binary);
        std::vector<std::string> arguments;
        std::string item;
        while (std::getline(file, item, '\0'))
            arguments.push_back(item);
        if (arguments.empty())
            continue;
        size_t slash = arguments[0].find_last_of('/');
        std::string name = arguments[0].substr(slash == std::string::npos ? 0 : slash + 1);
        if (name != program)
            continue;
        bool specific = false;
        for (size_t index = 1; index < arguments.size(); ++index) {
            if (arguments[index] == "-i" && index + 1 < arguments.size()) {
                specific = true;
                conflict |= arguments[index + 1] == interface;
            } else if (arguments[index].rfind("-i", 0) == 0 && arguments[index].size() > 2) {
                specific = true;
                conflict |= arguments[index].substr(2) == interface;
            }
        }
        if (!specific)
            conflict = true;
        if (conflict)
            break;
    }
    closedir(directory);
    return conflict;
}
} // namespace

namespace detail {
bool valid_interface(const std::string &name) {
    return !name.empty() && name.size() < IFNAMSIZ &&
           std::all_of(name.begin(), name.end(), [](unsigned char c) {
               return std::isalnum(c) || c == '_' || c == '-' || c == '.';
           });
}

bool valid_ssid(const std::string &ssid) {
    if (ssid.empty() || ssid.size() > 32)
        return false;
    size_t index = 0;
    while (index < ssid.size()) {
        unsigned char c = static_cast<unsigned char>(ssid[index++]);
        uint32_t code = 0;
        unsigned continuation = 0;
        uint32_t minimum = 0;
        if (c < 0x80) {
            code = c;
        } else if (c >= 0xc2 && c <= 0xdf) {
            code = c & 0x1f;
            continuation = 1;
            minimum = 0x80;
        } else if (c >= 0xe0 && c <= 0xef) {
            code = c & 0x0f;
            continuation = 2;
            minimum = 0x800;
        } else if (c >= 0xf0 && c <= 0xf4) {
            code = c & 7;
            continuation = 3;
            minimum = 0x10000;
        } else {
            return false;
        }
        while (continuation--) {
            if (index == ssid.size())
                return false;
            c = static_cast<unsigned char>(ssid[index++]);
            if ((c & 0xc0) != 0x80)
                return false;
            code = (code << 6) | (c & 0x3f);
        }
        if (code < minimum || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff) ||
            code < 0x20 || (code >= 0x7f && code <= 0x9f))
            return false;
    }
    return true;
}

std::string encode_hex(const std::string &value) {
    const char alphabet[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size() * 2);
    for (unsigned char c : value) {
        result += alphabet[c >> 4];
        result += alphabet[c & 15];
    }
    return result;
}

bool decode_hex(const std::string &value, std::string &decoded) {
    if (value.size() % 2)
        return false;
    auto nibble = [](unsigned char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    std::string result;
    for (size_t i = 0; i < value.size(); i += 2) {
        int first = nibble(value[i]);
        int second = nibble(value[i + 1]);
        if (first < 0 || second < 0)
            return false;
        result += static_cast<char>((first << 4) | second);
    }
    decoded = std::move(result);
    return true;
}

bool decode_wpa_string(const std::string &value, std::string &decoded) {
    std::string result;
    for (size_t index = 0; index < value.size(); ++index) {
        char c = value[index];
        if (c != '\\') {
            result += c;
            continue;
        }
        if (++index == value.size())
            return false;
        switch (value[index]) {
        case '\\':
            result += '\\';
            break;
        case '"':
            result += '"';
            break;
        case 'e':
            result += '\x1b';
            break;
        case 'n':
            result += '\n';
            break;
        case 'r':
            result += '\r';
            break;
        case 't':
            result += '\t';
            break;
        case 'x': {
            if (index + 2 >= value.size())
                return false;
            std::string byte;
            if (!decode_hex(value.substr(index + 1, 2), byte))
                return false;
            result += byte;
            index += 2;
            break;
        }
        default:
            return false;
        }
    }
    decoded = std::move(result);
    return true;
}

int frequency_channel(int frequency) {
    if (frequency == 2484)
        return 14;
    if (frequency >= 2412 && frequency <= 2472 && (frequency - 2407) % 5 == 0)
        return (frequency - 2407) / 5;
    if (frequency >= 5000 && frequency <= 5895 && frequency % 5 == 0)
        return (frequency - 5000) / 5;
    if (frequency >= 5955 && frequency <= 7115 && (frequency - 5950) % 5 == 0)
        return (frequency - 5950) / 5;
    return 0;
}

bool same_association_lease(const std::string &initial_status, const std::string &current_status,
                            const std::string &requested_ssid, const std::string &trial_id,
                            const std::string &initial_route, const std::string &current_route) {
    if (initial_route.empty() || initial_route != current_route || trial_id.empty())
        return false;
    auto initial = fields(initial_status);
    auto current = fields(current_status);
    if (initial["wpa_state"] != "COMPLETED" || current["wpa_state"] != "COMPLETED" ||
        current["id"] != trial_id)
        return false;
    std::string initial_ssid, current_ssid;
    if (!decode_wpa_string(initial["ssid"], initial_ssid) ||
        !decode_wpa_string(current["ssid"], current_ssid) || initial_ssid != requested_ssid ||
        current_ssid != requested_ssid)
        return false;
    auto normalized_bssid = [](std::string value) {
        if (value.size() != 17)
            return std::string();
        for (size_t index = 0; index < value.size(); ++index) {
            unsigned char c = static_cast<unsigned char>(value[index]);
            if ((index % 3 == 2 && c != ':') || (index % 3 != 2 && !std::isxdigit(c)))
                return std::string();
            value[index] = static_cast<char>(std::tolower(c));
        }
        return value == "00:00:00:00:00:00" ? std::string() : value;
    };
    const std::string initial_bssid = normalized_bssid(initial["bssid"]);
    return !initial_bssid.empty() && initial_bssid == normalized_bssid(current["bssid"]);
}

std::vector<AccessPoint> parse_scan_results(const std::string &text) {
    std::vector<AccessPoint> result;
    std::istringstream input(text);
    std::string line;
    std::getline(input, line); // Column header.
    while (std::getline(input, line)) {
        std::vector<std::string> columns;
        size_t start = 0;
        for (unsigned i = 0; i < 4; ++i) {
            size_t tab = line.find('\t', start);
            if (tab == std::string::npos)
                break;
            columns.push_back(line.substr(start, tab - start));
            start = tab + 1;
        }
        if (columns.size() != 4)
            continue;
        std::string ssid;
        if (!decode_wpa_string(line.substr(start), ssid) || !valid_ssid(ssid))
            continue;
        char *end = nullptr;
        long frequency = std::strtol(columns[1].c_str(), &end, 10);
        if (!end || *end || frequency < 0 || frequency > 10000)
            continue;
        long rssi = std::strtol(columns[2].c_str(), &end, 10);
        if (!end || *end || rssi < -150 || rssi > 0)
            continue;
        AccessPoint item;
        item.ssid = std::move(ssid);
        item.rssi = static_cast<int>(rssi);
        item.channel = frequency_channel(static_cast<int>(frequency));
        const std::string &flags = columns[3];
        // Match the common web API's ESP Wi-Fi auth mode values.
        if (flags.find("SAE") != std::string::npos)
            item.authmode = flags.find("PSK") != std::string::npos ? 7 : 6;
        else if (flags.find("EAP") != std::string::npos)
            item.authmode = 5;
        else if (flags.find("WPA2") != std::string::npos || flags.find("RSN") != std::string::npos)
            item.authmode = flags.find("[WPA-") != std::string::npos ? 4 : 3;
        else if (flags.find("WPA") != std::string::npos)
            item.authmode = 2;
        else if (flags.find("WEP") != std::string::npos)
            item.authmode = 1;
        auto duplicate = std::find_if(result.begin(), result.end(), [&](const AccessPoint &prior) {
            return prior.ssid == item.ssid;
        });
        if (duplicate == result.end())
            result.push_back(std::move(item));
        else if (duplicate->rssi < item.rssi)
            *duplicate = std::move(item);
    }
    std::sort(result.begin(), result.end(),
              [](const AccessPoint &a, const AccessPoint &b) { return a.rssi > b.rssi; });
    if (result.size() > 64)
        result.resize(64);
    return result;
}

bool read_credentials(int directory, std::vector<Credential> &credentials, std::string &error) {
    std::string text;
    if (!read_private_file(directory, kCredentialFile, text, error, true))
        return false;
    std::vector<Credential> result;
    if (text.empty()) {
        credentials.clear();
        return true;
    }
    std::istringstream input(text);
    std::string line;
    if (!std::getline(input, line) || line != "MYBOT_WIFI_V1") {
        error = "Unsupported Wi-Fi credential file";
        return false;
    }
    std::set<std::string> seen;
    while (std::getline(input, line)) {
        size_t tab = line.find('\t');
        Credential credential;
        if (tab == std::string::npos || !decode_hex(line.substr(0, tab), credential.ssid) ||
            !valid_ssid(credential.ssid)) {
            error = "Invalid Wi-Fi credential record";
            return false;
        }
        credential.psk = line.substr(tab + 1);
        if ((!credential.psk.empty() && !hex_psk(credential.psk)) || result.size() >= 10 ||
            !seen.insert(credential.ssid).second) {
            error = "Invalid or excessive Wi-Fi credential records";
            return false;
        }
        result.push_back(std::move(credential));
    }
    credentials = std::move(result);
    return true;
}

bool write_credentials(int directory, const std::vector<Credential> &credentials,
                       std::string &error) {
    if (credentials.size() > 10) {
        error = "At most 10 saved Wi-Fi networks are supported";
        return false;
    }
    std::set<std::string> seen;
    std::string text = "MYBOT_WIFI_V1\n";
    for (const auto &credential : credentials) {
        if (!valid_ssid(credential.ssid) || (!credential.psk.empty() && !hex_psk(credential.psk)) ||
            !seen.insert(credential.ssid).second) {
            error = "Invalid or duplicate Wi-Fi credentials";
            return false;
        }
        text += encode_hex(credential.ssid) + "\t" + credential.psk + "\n";
    }
    return atomic_private_file(directory, kCredentialFile, text, error);
}

bool command(const std::vector<std::string> &arguments, unsigned timeout_ms,
             const std::atomic<bool> *cancel, std::string &output, std::string &error) {
    output.clear();
    if (cancel && cancel->load()) {
        error = "Wi-Fi operation cancelled";
        return false;
    }
    int descriptors[2];
    if (pipe(descriptors)) {
        error = "Cannot capture Wi-Fi helper output";
        return false;
    }
    fcntl(descriptors[0], F_SETFD, FD_CLOEXEC);
    fcntl(descriptors[1], F_SETFD, FD_CLOEXEC);
    fcntl(descriptors[0], F_SETFL, O_NONBLOCK);
    Child process;
    if (!process.start(arguments, descriptors[1], error)) {
        close(descriptors[0]);
        close(descriptors[1]);
        return false;
    }
    close(descriptors[1]);
    auto end = Clock::now() + std::chrono::milliseconds(timeout_ms);
    bool failed = false;
    for (;;) {
        char buffer[4096];
        ssize_t bytes;
        while ((bytes = read(descriptors[0], buffer, sizeof(buffer))) > 0) {
            if (output.size() + static_cast<size_t>(bytes) > kMaxOutput) {
                failed = true;
                error = "Wi-Fi helper output exceeded limit";
                break;
            }
            output.append(buffer, static_cast<size_t>(bytes));
        }
        if (failed || (cancel && cancel->load()) || Clock::now() >= end) {
            if (!failed)
                error = cancel && cancel->load() ? "Wi-Fi operation cancelled"
                                                 : "Wi-Fi helper timed out";
            failed = true;
            break;
        }
        if (!process.running()) {
            // Reap is followed by another read so fast commands retain all output.
            while ((bytes = read(descriptors[0], buffer, sizeof(buffer))) > 0) {
                if (output.size() + static_cast<size_t>(bytes) > kMaxOutput) {
                    failed = true;
                    error = "Wi-Fi helper output exceeded limit";
                    break;
                }
                output.append(buffer, static_cast<size_t>(bytes));
            }
            break;
        }
        pollfd wait{descriptors[0], POLLIN, 0};
        poll(&wait, 1, 20);
    }
    close(descriptors[0]);
    if (failed) {
        process.stop();
        return false;
    }
    if (!process.succeeded()) {
        error = "Wi-Fi helper failed: " + (arguments.empty() ? std::string() : arguments[0]);
        return false;
    }
    return true;
}
} // namespace detail

bool make_credential(const std::string &ssid, const std::string &password, Credential &credential,
                     std::string &error) {
    if (!detail::valid_ssid(ssid)) {
        error = "SSID must contain 1–32 UTF-8 bytes without control characters";
        return false;
    }
    Credential result;
    result.ssid = ssid;
    if (password.empty()) {
        credential = std::move(result);
        return true;
    }
    if (hex_psk(password)) {
        result.psk = password;
        std::transform(result.psk.begin(), result.psk.end(), result.psk.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    } else {
        if (password.size() < 8 || password.size() > 63 ||
            std::any_of(password.begin(), password.end(),
                        [](unsigned char c) { return c < 0x20 || c == 0x7f; })) {
            error = "Password must contain 8–63 bytes, a 64-digit hexadecimal PSK, or be empty";
            return false;
        }
        unsigned char key[32];
        if (PKCS5_PBKDF2_HMAC_SHA1(password.data(), static_cast<int>(password.size()),
                                   reinterpret_cast<const unsigned char *>(ssid.data()),
                                   static_cast<int>(ssid.size()), 4096, sizeof(key), key) != 1) {
            error = "Cannot derive Wi-Fi key";
            return false;
        }
        result.psk = detail::encode_hex(std::string(reinterpret_cast<char *>(key), sizeof(key)));
        OPENSSL_cleanse(key, sizeof(key));
    }
    credential = std::move(result);
    return true;
}

namespace {
class LinuxBackend final : public Backend {
  public:
    explicit LinuxBackend(BackendConfig config) : config_(std::move(config)) {
    }
    ~LinuxBackend() override {
        stop_ap();
        stop_dhcp();
        remove_trial();
        supplicant_.stop();
        control_.close_socket();
        if (storage_fd_ >= 0)
            close(storage_fd_);
        if (runtime_fd_ >= 0) {
            // Every file in this private, process-owned directory is ours.
            DIR *directory = fdopendir(dup(runtime_fd_));
            if (directory) {
                while (dirent *entry = readdir(directory)) {
                    if (entry->d_name[0] == '.')
                        continue;
                    unlinkat(runtime_fd_, entry->d_name, 0);
                }
                closedir(directory);
            }
            unlinkat(runtime_fd_, "wpa", AT_REMOVEDIR);
            unlinkat(runtime_fd_, "hostapd", AT_REMOVEDIR);
            close(runtime_fd_);
            rmdir(runtime_.c_str());
        }
    }

    bool initialize(std::string &error) override {
#ifndef __linux__
        error = "Wi-Fi AP provisioning requires Linux nl80211";
        return false;
#else
        if (initialized_)
            return true;
        interface_ = config_.interface_name;
        if (interface_.empty()) {
            std::vector<std::string> names;
            DIR *directory = opendir("/sys/class/net");
            if (directory) {
                while (dirent *entry = readdir(directory)) {
                    std::string name = entry->d_name;
                    struct stat st {};
                    if (detail::valid_interface(name) &&
                        stat(("/sys/class/net/" + name + "/phy80211").c_str(), &st) == 0)
                        names.push_back(name);
                }
                closedir(directory);
            }
            std::sort(names.begin(), names.end());
            auto wlan0 = std::find(names.begin(), names.end(), "wlan0");
            if (!names.empty())
                interface_ = wlan0 == names.end() ? names.front() : *wlan0;
        }
        struct stat wireless {};
        if (!detail::valid_interface(interface_) ||
            stat(("/sys/class/net/" + interface_ + "/phy80211").c_str(), &wireless) != 0) {
            error = "No nl80211 Wi-Fi interface; configure the Wi-Fi interface explicitly";
            return false;
        }
        std::string mac = read_text("/sys/class/net/" + interface_ + "/address");
        if (mac.size() < 5 || mac[2] != ':' || !std::isxdigit(static_cast<unsigned char>(mac[0])) ||
            !std::isxdigit(static_cast<unsigned char>(mac[1])) ||
            !std::isxdigit(static_cast<unsigned char>(mac[3])) ||
            !std::isxdigit(static_cast<unsigned char>(mac[4]))) {
            error = "Cannot read Wi-Fi MAC address";
            return false;
        }
        ssid_ = "mybot-" + mac.substr(0, 2) + mac.substr(3, 2);
        std::transform(ssid_.begin(), ssid_.end(), ssid_.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        for (const char *name : {"ip", "iw", "hostapd", "dnsmasq", "wpa_supplicant", "udhcpc"}) {
            programs_[name] = find_program(name);
            if (programs_[name].empty()) {
                error = std::string("Missing required Wi-Fi tool: ") + name;
                return false;
            }
        }
        struct stat script {};
        if (config_.dhcp_script.empty() || config_.dhcp_script[0] != '/' ||
            lstat(config_.dhcp_script.c_str(), &script) != 0 || !S_ISREG(script.st_mode) ||
            (script.st_mode & 0022) || access(config_.dhcp_script.c_str(), X_OK) != 0) {
            error = "Missing or unsafe executable Wi-Fi DHCP hook";
            return false;
        }
        int base = -1;
        if (!private_directory(config_.storage_directory, base, error))
            return false;
        close(base);
        if (!private_directory(config_.storage_directory + "/wifi", storage_fd_, error))
            return false;
        std::string runtime_base = config_.runtime_directory.empty() ? "/run/mybot-rv1126b-wifi"
                                                                     : config_.runtime_directory;
        if (!private_directory(runtime_base, base, error))
            return false;
        close(base);
        std::string pattern = runtime_base + "/session-XXXXXX";
        std::vector<char> path(pattern.begin(), pattern.end());
        path.push_back('\0');
        char *created = mkdtemp(path.data());
        if (!created) {
            error = "Cannot create private Wi-Fi runtime session";
            return false;
        }
        runtime_ = created;
        if (runtime_.size() > 72 || !private_directory(runtime_, runtime_fd_, error)) {
            error = "Wi-Fi runtime path is unsafe or too long for Unix control sockets";
            rmdir(runtime_.c_str());
            return false;
        }
        initialized_ = true;
        return true;
#endif
    }

    std::string ap_ssid() const override {
        return ssid_;
    }
    bool concurrent_ap() const override {
        return concurrent_;
    }

    bool start_ap(std::string &error) override {
        if (!initialized_ && !initialize(error))
            return false;
        if (ap_running())
            return true;
        stop_ap();
        if (control_.request("PING", 100).rfind("PONG", 0) != 0 && !owns_supplicant_)
            attach_supplicant();
        if (control_.request("PING", 100).rfind("PONG", 0) == 0)
            cached_scan_ = detail::parse_scan_results(control_.request("SCAN_RESULTS", 200));
        std::string output;
        ap_interface_ = "mbap" + std::to_string(getpid() % 1000000);
        if (if_nametoindex(ap_interface_.c_str()) == 0 &&
            run({"iw", "dev", interface_, "interface", "add", ap_interface_, "type", "__ap"},
                output, error)) {
            virtual_ap_ = true;
            concurrent_ = true;
        } else {
            ap_interface_.clear();
            concurrent_ = false;
            // An external supplicant cannot safely share its station interface with hostapd.
            if (!owns_supplicant_ &&
                (attach_supplicant() || process_uses_interface("wpa_supplicant", interface_) ||
                 process_uses_interface("hostapd", interface_))) {
                error = "Driver cannot create an AP+STA interface; existing Wi-Fi manager owns "
                        "the station. Provide AP+STA support or hand off this interface explicitly";
                return false;
            }
            stop_dhcp();
            remove_trial();
            control_.close_socket();
            supplicant_.stop();
            owns_supplicant_ = true;
            ap_interface_ = interface_;
        }
        int channel = 1;
        auto status = fields(control_.request("STATUS", 200));
        auto frequency = status.find("freq");
        if (frequency != status.end()) {
            int candidate = detail::frequency_channel(std::atoi(frequency->second.c_str()));
            if (candidate >= 1 && candidate <= 14)
                channel = candidate;
            else if (candidate > 14) {
                error = "Current station uses 5/6 GHz; move it to 2.4 GHz before provisioning";
                stop_ap();
                return false;
            }
        }
        // ssid2 hex avoids hostapd configuration injection and preserves UTF-8.
        std::string configuration =
            "interface=" + ap_interface_ + "\ndriver=nl80211\nssid2=" + detail::encode_hex(ssid_) +
            "\nhw_mode=g\nchannel=" + std::to_string(channel) + "\nmax_num_sta=4\nauth_algs=1\n" +
            "wpa=0\nap_isolate=1\nctrl_interface=" + runtime_ + "/hostapd\n";
        if (!atomic_private_file(runtime_fd_, "hostapd.conf", configuration, error) ||
            !run({"ip", "link", "set", "dev", ap_interface_, "up"}, output, error)) {
            stop_ap();
            return false;
        }
        if (has_address(ap_interface_, "192.168.4.1")) {
            error = "Provisioning address 192.168.4.1 is already owned on the AP interface";
            stop_ap();
            return false;
        }
        if (!run({"ip", "address", "add", "192.168.4.1/24", "dev", ap_interface_}, output, error)) {
            stop_ap();
            return false;
        }
        ap_address_ = true;
        if (!hostapd_.start({programs_["hostapd"], runtime_ + "/hostapd.conf"}, -1, error)) {
            stop_ap();
            return false;
        }
        // A living process is insufficient: wait for the driver's ENABLED state.
        bool enabled = false;
        auto deadline = Clock::now() + std::chrono::seconds(4);
        while (hostapd_.running() && Clock::now() < deadline) {
            Control ap_control;
            if (ap_control.open_socket(runtime_ + "/hostapd/" + ap_interface_,
                                       runtime_ + "/ap-client")) {
                auto values = fields(ap_control.request("STATUS", 200));
                enabled = values["state"] == "ENABLED";
                if (enabled)
                    break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        if (!enabled) {
            error = "hostapd did not enable the AP (check driver, regulatory domain and channel)";
            stop_ap();
            return false;
        }
        std::vector<std::string> dhcp = {programs_["dnsmasq"],
                                         "--keep-in-foreground",
                                         "--conf-file=/dev/null",
                                         "--port=0",
                                         "--interface=" + ap_interface_,
                                         "--bind-interfaces",
                                         "--except-interface=lo",
                                         "--dhcp-range=192.168.4.2,192.168.4.5,255.255.255.0,10m",
                                         "--dhcp-option=3,192.168.4.1",
                                         "--dhcp-option=6,192.168.4.1",
                                         "--dhcp-lease-max=4",
                                         "--dhcp-leasefile=" + runtime_ + "/leases",
                                         "--pid-file=" + runtime_ + "/dnsmasq.pid"};
        if (geteuid() == 0)
            dhcp.push_back("--user=root");
        if (!dnsmasq_.start(dhcp, -1, error)) {
            stop_ap();
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (!hostapd_.running() || !dnsmasq_.running()) {
            error = "AP DHCP service failed to start; check port 67 ownership and privileges";
            stop_ap();
            return false;
        }
        ap_ready_ = true;
        error.clear();
        return true;
    }

    void stop_ap() override {
        ap_ready_ = false;
        dnsmasq_.stop();
        hostapd_.stop();
        std::string output, error;
        if (ap_address_ && !ap_interface_.empty())
            run({"ip", "address", "del", "192.168.4.1/24", "dev", ap_interface_}, output, error);
        ap_address_ = false;
        if (virtual_ap_ && !ap_interface_.empty())
            run({"iw", "dev", ap_interface_, "del"}, output, error);
        virtual_ap_ = false;
        ap_interface_.clear();
        if (runtime_fd_ >= 0) {
            unlinkat(runtime_fd_, "hostapd.conf", 0);
            unlinkat(runtime_fd_, "leases", 0);
            unlinkat(runtime_fd_, "dnsmasq.pid", 0);
        }
    }

    bool ap_running() override {
        return ap_ready_ && hostapd_.running() && dnsmasq_.running();
    }

    bool online() const override {
#ifdef __linux__
        if (interface_.empty())
            return false;
        std::ifstream routes("/proc/net/route");
        std::string line;
        bool routed = false;
        while (std::getline(routes, line)) {
            char name[IFNAMSIZ]{};
            unsigned long destination = 0, gateway = 0, flags = 0, mask = 0;
            if (std::sscanf(line.c_str(), "%15s %lx %lx %lx %*u %*u %*u %lx", name, &destination,
                            &gateway, &flags, &mask) == 5 &&
                interface_ == name && destination == 0 && mask == 0 && (flags & 1UL) &&
                !(flags & 0x200UL)) {
                routed = true;
                break;
            }
        }
        if (!routed)
            return false;
        ifaddrs *addresses = nullptr;
        if (getifaddrs(&addresses) != 0)
            return false;
        bool found = false;
        for (ifaddrs *item = addresses; item; item = item->ifa_next) {
            if (!item->ifa_addr || item->ifa_addr->sa_family != AF_INET ||
                interface_ != item->ifa_name || !(item->ifa_flags & IFF_UP) ||
                !(item->ifa_flags & IFF_RUNNING) || (item->ifa_flags & IFF_LOOPBACK))
                continue;
            uint32_t address =
                ntohl(reinterpret_cast<sockaddr_in *>(item->ifa_addr)->sin_addr.s_addr);
            if (address && (address >> 24) != 127 && (address >> 16) != 0xa9fe &&
                (address >> 28) < 14 && address != 0xc0a80401U) {
                found = true;
                break;
            }
        }
        freeifaddrs(addresses);
        return found;
#else
        return false;
#endif
    }

    std::vector<AccessPoint> scan(std::string &error) override {
        if (!initialized_ && !initialize(error))
            return {};
        if (!concurrent_ && ap_running()) {
            // Keep the AP available: cached results and manual SSID entry remain usable.
            if (cached_scan_.empty())
                error = "Active scanning is unavailable while this single-interface AP is running; "
                        "enter a hidden SSID manually";
            else
                error.clear();
            return cached_scan_;
        }
        if (!ensure_supplicant(error))
            return {};
        std::string response = control_.request("SCAN");
        if (response.rfind("OK", 0) != 0 && response.find("FAIL-BUSY") == std::string::npos) {
            error = "Wi-Fi driver rejected scanning";
            return {};
        }
        // Supplicant scanning is asynchronous; its most recent cached results stay useful.
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        response = control_.request("SCAN_RESULTS");
        if (response.rfind("bssid", 0) != 0) {
            error = "Cannot read Wi-Fi scan results";
            return {};
        }
        error.clear();
        cached_scan_ = detail::parse_scan_results(response);
        return cached_scan_;
    }

    std::vector<Credential> load(std::string &error) override {
        std::vector<Credential> result;
        if ((!initialized_ && !initialize(error)) ||
            !detail::read_credentials(storage_fd_, result, error))
            return {};
        error.clear();
        return result;
    }

    bool save(const std::vector<Credential> &credentials, std::string &error) override {
        if (!initialized_ && !initialize(error))
            return false;
        return detail::write_credentials(storage_fd_, credentials, error);
    }

    bool connect(const Credential &credential, unsigned timeout_ms, const std::atomic<bool> &cancel,
                 std::string &error) override {
        if (!detail::valid_ssid(credential.ssid) ||
            (!credential.psk.empty() && !hex_psk(credential.psk))) {
            error = "Invalid Wi-Fi credentials";
            return false;
        }
        if (cancel.load()) {
            error = "Wi-Fi operation cancelled";
            return false;
        }
        if (!initialized_ && !initialize(error))
            return false;
        // Snapshot identity and routing before removing any previous owned trial. An existing
        // manager may legitimately keep the same lease when reconnecting to the very same AP.
        std::string initial_status = control_.request("STATUS", 200);
        if (initial_status.empty() && !owns_supplicant_ && attach_supplicant())
            initial_status = control_.request("STATUS", 200);
        const std::string original_route = routed_fingerprint();
        if (!concurrent_ && ap_running())
            stop_ap();
        stop_dhcp();
        remove_trial();
        if (!ensure_supplicant(error))
            return false;
        std::string number = control_.request("ADD_NETWORK");
        if (!number.empty() && number.back() == '\n')
            number.pop_back();
        if (number.empty() || number.size() > 8 ||
            !std::all_of(number.begin(), number.end(),
                         [](unsigned char c) { return std::isdigit(c); })) {
            error = "Cannot create temporary supplicant network";
            return false;
        }
        trial_ = number;
        bool configured =
            control_.ok("SET_NETWORK " + trial_ + " ssid " + detail::encode_hex(credential.ssid)) &&
            control_.ok("SET_NETWORK " + trial_ + " scan_ssid 1") &&
            control_.ok("SET_NETWORK " + trial_ + " priority 2147483647") &&
            control_.ok("SET_NETWORK " + trial_ + " key_mgmt " +
                        (credential.psk.empty() ? "NONE" : "WPA-PSK"));
        if (configured && !credential.psk.empty())
            configured = control_.ok("SET_NETWORK " + trial_ + " psk " + credential.psk);
        if (!configured || !control_.ok("ENABLE_NETWORK " + trial_) ||
            !control_.ok("REASSOCIATE")) {
            error = "Supplicant rejected temporary network configuration";
            remove_trial();
            return false;
        }
        auto deadline = Clock::now() + std::chrono::milliseconds(std::min(timeout_ms, 120000U));
        bool associated = false;
        while (!cancel.load() && Clock::now() < deadline) {
            const std::string current_status = control_.request("STATUS", 200);
            auto status = fields(current_status);
            std::string current_ssid;
            associated = status["wpa_state"] == "COMPLETED" && status["id"] == trial_ &&
                         detail::decode_wpa_string(status["ssid"], current_ssid) &&
                         current_ssid == credential.ssid;
            if (associated) {
                if (!dhcp_started_) {
                    // An existing DHCP manager keeps ownership; only start our client when absent.
                    if (!process_uses_interface("udhcpc", interface_) &&
                        !process_uses_interface("dhcpcd", interface_) &&
                        !process_uses_interface("dhclient", interface_)) {
                        if (!start_dhcp(error)) {
                            remove_trial();
                            return false;
                        }
                    }
                    dhcp_started_ = true;
                }
                const std::string current_route = routed_fingerprint();
                const bool fresh_lease =
                    dhcp_owned_ ? access((runtime_ + "/lease.ready").c_str(), R_OK) == 0
                                : current_route != original_route;
                const bool same_network_lease =
                    !dhcp_owned_ &&
                    detail::same_association_lease(initial_status, current_status, credential.ssid,
                                                   trial_, original_route, current_route);
                if (online() && (fresh_lease || same_network_lease)) {
                    error.clear();
                    return true;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        error = cancel.load() ? "Wi-Fi operation cancelled"
                : associated ? "Wi-Fi associated but no fresh routed IPv4 lease was obtained; hand "
                               "off the DHCP manager if its previous lease is unchanged"
                             : "Wi-Fi connection timed out; verify SSID and password";
        stop_dhcp();
        remove_trial();
        return false;
    }

  private:
    bool run(std::vector<std::string> arguments, std::string &output, std::string &error) {
        if (arguments.empty() || !programs_.count(arguments[0]) ||
            programs_[arguments[0]].empty()) {
            error = "Missing required Wi-Fi executable";
            return false;
        }
        arguments[0] = programs_[arguments[0]];
        return detail::command(arguments, kCommandTimeout, nullptr, output, error);
    }

    static bool has_address(const std::string &interface, const std::string &address) {
        ifaddrs *addresses = nullptr;
        if (getifaddrs(&addresses) != 0)
            return false;
        bool found = false;
        for (ifaddrs *item = addresses; item; item = item->ifa_next) {
            if (!item->ifa_addr || item->ifa_addr->sa_family != AF_INET ||
                interface != item->ifa_name)
                continue;
            char text[INET_ADDRSTRLEN];
            auto *value = reinterpret_cast<sockaddr_in *>(item->ifa_addr);
            if (inet_ntop(AF_INET, &value->sin_addr, text, sizeof(text)) && address == text) {
                found = true;
                break;
            }
        }
        freeifaddrs(addresses);
        return found;
    }

    std::string routed_fingerprint() const {
        if (!online())
            return {};
        std::string result;
        ifaddrs *addresses = nullptr;
        if (getifaddrs(&addresses) == 0) {
            for (ifaddrs *item = addresses; item; item = item->ifa_next) {
                if (item->ifa_addr && item->ifa_addr->sa_family == AF_INET &&
                    interface_ == item->ifa_name) {
                    const auto *address = reinterpret_cast<const sockaddr_in *>(item->ifa_addr);
                    result += std::to_string(address->sin_addr.s_addr) + ";";
                }
            }
            freeifaddrs(addresses);
        }
        std::istringstream routes(read_text("/proc/net/route"));
        std::string line;
        while (std::getline(routes, line)) {
            if (line.rfind(interface_ + "\t", 0) == 0 || line.rfind(interface_ + " ", 0) == 0)
                result += line;
        }
        return result;
    }

    bool attach_supplicant() {
        for (const char *base : {"/run/wpa_supplicant/", "/var/run/wpa_supplicant/"}) {
            if (control_.open_socket(std::string(base) + interface_, runtime_ + "/wpa-client") &&
                control_.request("PING", 200).rfind("PONG", 0) == 0)
                return true;
        }
        control_.close_socket();
        return false;
    }

    bool ensure_supplicant(std::string &error) {
        if (control_.request("PING", 200).rfind("PONG", 0) == 0)
            return true;
        if (!owns_supplicant_ && attach_supplicant())
            return true;
        if (!supplicant_.running()) {
            if (!owns_supplicant_ && process_uses_interface("wpa_supplicant", interface_)) {
                error = "Existing supplicant has no accessible control socket; hand off Wi-Fi "
                        "management or expose its per-interface control socket";
                return false;
            }
            owns_supplicant_ = true;
            std::string configuration = "ctrl_interface=" + runtime_ + "/wpa\nupdate_config=0\n";
            if (!atomic_private_file(runtime_fd_, "wpa.conf", configuration, error) ||
                !supplicant_.start({programs_["wpa_supplicant"], "-Dnl80211", "-i", interface_,
                                    "-c", runtime_ + "/wpa.conf"},
                                   -1, error))
                return false;
        }
        auto deadline = Clock::now() + std::chrono::seconds(3);
        while (supplicant_.running() && Clock::now() < deadline) {
            if (control_.open_socket(runtime_ + "/wpa/" + interface_, runtime_ + "/wpa-client") &&
                control_.request("PING", 100).rfind("PONG", 0) == 0)
                return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        error = "Owned wpa_supplicant did not expose a working control socket";
        return false;
    }

    void remove_trial() {
        if (trial_.empty())
            return;
        // Only our in-memory profile is removed; external enabled flags are untouched.
        control_.ok("REMOVE_NETWORK " + trial_);
        control_.ok("REASSOCIATE");
        trial_.clear();
    }

    bool start_dhcp(std::string &error) {
        std::map<std::string, std::string> environment = {{"MYBOT_WIFI_RUNTIME", runtime_},
                                                          {"MYBOT_WIFI_INTERFACE", interface_}};
        dhcp_owned_ = dhcp_.start({programs_["udhcpc"], "-f", "-R", "-i", interface_, "-s",
                                   config_.dhcp_script, "-p", runtime_ + "/udhcpc.pid", "-t", "3",
                                   "-T", "3", "-A", "2"},
                                  -1, error, environment);
        return dhcp_owned_;
    }

    void stop_dhcp() {
        dhcp_.stop();
        if (dhcp_owned_ && !runtime_.empty()) {
            Child cleanup;
            std::string error;
            if (cleanup.start(
                    {config_.dhcp_script, "mybot-cleanup"}, -1, error,
                    {{"MYBOT_WIFI_RUNTIME", runtime_}, {"MYBOT_WIFI_INTERFACE", interface_}})) {
                auto deadline = Clock::now() + std::chrono::milliseconds(500);
                while (cleanup.running() && Clock::now() < deadline)
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
        dhcp_started_ = false;
        dhcp_owned_ = false;
    }

    BackendConfig config_;
    bool initialized_ = false;
    bool owns_supplicant_ = false;
    bool concurrent_ = true;
    bool virtual_ap_ = false;
    bool ap_address_ = false;
    bool ap_ready_ = false;
    bool dhcp_started_ = false;
    bool dhcp_owned_ = false;
    int storage_fd_ = -1;
    int runtime_fd_ = -1;
    std::string interface_;
    std::string ap_interface_;
    std::string ssid_;
    std::string runtime_;
    std::string trial_;
    std::map<std::string, std::string> programs_;
    std::vector<AccessPoint> cached_scan_;
    Child hostapd_, dnsmasq_, supplicant_, dhcp_;
    Control control_;
};
} // namespace

std::unique_ptr<Backend> make_linux_backend(const BackendConfig &config) {
    return std::unique_ptr<Backend>(new LinuxBackend(config));
}
} // namespace rv1126b_wifi
