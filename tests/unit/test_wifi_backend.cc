/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_backend_internal.h"
#include "check.h"
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <climits>
#include <cerrno>
#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <thread>

using namespace rv1126b_wifi;

static void credentials() {
    Credential credential;
    std::string error;
    CHECK(make_credential("IEEE", "password", credential, error));
    CHECK(credential.psk == "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e");
    CHECK(make_credential("中文网络", "12345678", credential, error));
    CHECK(credential.psk.size() == 64);
    CHECK(make_credential("open", "", credential, error) && credential.psk.empty());
    CHECK(make_credential("raw", std::string(64, 'A'), credential, error));
    CHECK(credential.psk == std::string(64, 'a'));
    CHECK(!make_credential("", "password", credential, error));
    CHECK(!make_credential(std::string(33, 'a'), "password", credential, error));
    CHECK(!make_credential("ssid", "short", credential, error));
    CHECK(!make_credential("ssid", std::string(64, 'g'), credential, error));
    CHECK(!make_credential("ssid", std::string("pass\0word", 9), credential, error));
    CHECK(!make_credential("injected\nnetwork={", "password", credential, error));
    CHECK(!detail::valid_ssid(std::string("zero\0end", 8)));
    CHECK(!detail::valid_ssid(std::string("\xc0\x80", 2)));
    CHECK(!detail::valid_ssid(std::string("\xed\xa0\x80", 3)));
    CHECK(!detail::valid_ssid(std::string("\xf4\x90\x80\x80", 4)));
    CHECK(!detail::valid_ssid(std::string("\xc2\x85", 2)));
    CHECK(detail::valid_interface("wlan0"));
    CHECK(!detail::valid_interface("wlan0;reboot"));
    CHECK(!detail::valid_interface("../../wlan0"));
    CHECK(!detail::valid_interface(std::string(16, 'a')));
}

static void parsing() {
    std::string decoded;
    CHECK(detail::decode_hex("c3a9", decoded) && decoded == "é");
    CHECK(!detail::decode_hex("0", decoded));
    CHECK(!detail::decode_hex("x1", decoded));
    CHECK(detail::decode_wpa_string("my\\x20wifi\\\\name", decoded));
    CHECK(decoded == "my wifi\\name");
    CHECK(!detail::decode_wpa_string("bad\\x0", decoded));
    CHECK(!detail::decode_wpa_string("bad\\q", decoded));
    const std::string scan =
        "bssid / frequency / signal level / flags / ssid\n"
        "00:01:02:03:04:05\t2412\t-81\t[WPA2-PSK-CCMP][ESS]\thome\\x20network\n"
        "00:01:02:03:04:06\t2462\t-40\t[WPA2-PSK-CCMP][ESS]\thome network\n"
        "00:01:02:03:04:07\t5180\t-20\t[SAE-CCMP][ESS]\tmodern\n"
        "00:01:02:03:04:08\t2484\t-60\t[ESS]\tpublic\n"
        "00:01:02:03:04:09\t2412\t-10\t[ESS]\tbad\\x0aSSID\n"
        "00:01:02:03:04:0a\txyz\t-50\t[ESS]\tbad number\n"
        "00:01:02:03:04:0b\t2412\t999\t[ESS]\tbad rssi\n"
        "00:01:02:03:04:0c\t2412\t-20\t[ESS]\t\n";
    auto points = detail::parse_scan_results(scan);
    CHECK(points.size() == 3);
    CHECK(points[0].ssid == "modern" && points[0].channel == 36 && points[0].authmode == 6);
    CHECK(points[1].ssid == "home network" && points[1].rssi == -40 && points[1].channel == 11);
    CHECK(points[1].authmode == 3);
    CHECK(points[2].ssid == "public" && points[2].channel == 14 && points[2].authmode == 0);
    CHECK(detail::frequency_channel(5955) == 1);
    CHECK(detail::frequency_channel(2413) == 0);
}

static void same_network_lease() {
    const std::string original = "wpa_state=COMPLETED\nssid=home\\x20network\n"
                                 "bssid=02:11:22:33:44:AA\nid=7\n";
    const std::string current = "wpa_state=COMPLETED\nssid=home network\n"
                                "bssid=02:11:22:33:44:aa\nid=42\n";
    auto reuse = [&](const std::string &before, const std::string &after,
                     const std::string &initial_route = "routed-ipv4",
                     const std::string &current_route = "routed-ipv4") {
        return detail::same_association_lease(before, after, "home network", "42", initial_route,
                                              current_route);
    };
    CHECK(reuse(original, current));
    CHECK(!reuse(original, current, "", ""));
    CHECK(!reuse(original, current, "old-route", "new-route"));
    CHECK(!reuse(original, "wpa_state=COMPLETED\nssid=other-network\n"
                           "bssid=02:11:22:33:44:aa\nid=42\n"));
    CHECK(!reuse("wpa_state=COMPLETED\nssid=other-network\n"
                 "bssid=02:11:22:33:44:aa\nid=7\n",
                 current));
    CHECK(!reuse(original, "wpa_state=COMPLETED\nssid=home network\n"
                           "bssid=02:11:22:33:44:ab\nid=42\n"));
    CHECK(!reuse(original, "wpa_state=COMPLETED\nssid=home network\n"
                           "bssid=\nid=42\n"));
    CHECK(!reuse("wpa_state=COMPLETED\nssid=home network\n"
                 "bssid=\nid=7\n",
                 current));
    CHECK(!reuse("wpa_state=ASSOCIATING\nssid=home network\n"
                 "bssid=02:11:22:33:44:aa\nid=7\n",
                 current));
    CHECK(!reuse(original, "wpa_state=ASSOCIATING\nssid=home network\n"
                           "bssid=02:11:22:33:44:aa\nid=42\n"));
    CHECK(!reuse(original, "wpa_state=COMPLETED\nssid=home network\n"
                           "bssid=02:11:22:33:44:aa\nid=7\n"));
}

static void store() {
    char temporary[] = "/tmp/mybot-wifi-store-XXXXXX";
    CHECK(mkdtemp(temporary));
    int directory = open(temporary, O_RDONLY | O_DIRECTORY);
    CHECK(directory >= 0);
    std::vector<Credential> values;
    std::string error;
    CHECK(detail::read_credentials(directory, values, error) && values.empty());
    Credential first, second;
    CHECK(make_credential("中文网络", "password", first, error));
    CHECK(make_credential("ssid\"; / !", "", second, error));
    CHECK(detail::write_credentials(directory, {first, second}, error));
    struct stat st {};
    CHECK(fstatat(directory, "wifi.credentials", &st, 0) == 0);
    CHECK((st.st_mode & 0777) == 0600);
    CHECK(detail::read_credentials(directory, values, error));
    CHECK(values.size() == 2 && values[0].ssid == first.ssid && values[0].psk == first.psk);
    std::ifstream raw(std::string(temporary) + "/wifi.credentials");
    std::string bytes((std::istreambuf_iterator<char>(raw)), std::istreambuf_iterator<char>());
    CHECK(bytes.find("password") == std::string::npos);
    CHECK(bytes.find(first.ssid) == std::string::npos);
    CHECK(!detail::write_credentials(directory, {first, first}, error));
    std::vector<Credential> excessive;
    for (int index = 0; index < 11; ++index)
        excessive.push_back({"ssid" + std::to_string(index), ""});
    CHECK(!detail::write_credentials(directory, excessive, error));
    CHECK(detail::read_credentials(directory, values, error) && values.size() == 2);
    CHECK(fchmodat(directory, "wifi.credentials", 0644, 0) == 0);
    CHECK(!detail::read_credentials(directory, values, error));
    CHECK(fchmodat(directory, "wifi.credentials", 0600, 0) == 0);
    CHECK(unlinkat(directory, "wifi.credentials", 0) == 0);
    CHECK(symlinkat("/dev/null", directory, "wifi.credentials") == 0);
    CHECK(!detail::read_credentials(directory, values, error));
    CHECK(!detail::write_credentials(directory, {first}, error));
    CHECK(unlinkat(directory, "wifi.credentials", 0) == 0);
    CHECK(detail::write_credentials(directory, {}, error));
    CHECK(detail::read_credentials(directory, values, error) && values.empty());
    CHECK(unlinkat(directory, "wifi.credentials", 0) == 0);
    // An attacker-created temporary symlink is not followed or replaced.
    std::string temporary_name = "wifi.credentials.new-" + std::to_string(getpid());
    CHECK(symlinkat("/dev/null", directory, temporary_name.c_str()) == 0);
    CHECK(!detail::write_credentials(directory, {first}, error));
    CHECK(unlinkat(directory, temporary_name.c_str(), 0) == 0);
    int corrupt = openat(directory, "wifi.credentials", O_CREAT | O_WRONLY, 0600);
    CHECK(corrupt >= 0);
    CHECK(write(corrupt, "MYBOT_WIFI_V1\nzz\t\n", 18) == 18);
    close(corrupt);
    CHECK(!detail::read_credentials(directory, values, error));
    CHECK(unlinkat(directory, "wifi.credentials", 0) == 0);
    close(directory);
    CHECK(rmdir(temporary) == 0);
}

static void processes(const std::string &self) {
    std::string output, error;
    CHECK(detail::command({"/bin/echo", "$(touch /tmp/unsafe); secret ' \""}, 1000, nullptr, output,
                          error));
    CHECK(output == "$(touch /tmp/unsafe); secret ' \"\n");
    CHECK(!detail::command({"/nonexistent/mybot-helper"}, 1000, nullptr, output, error));
    auto start = std::chrono::steady_clock::now();
    CHECK(!detail::command({self, "--ignore-term"}, 80, nullptr, output, error));
    CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(2));
    CHECK(error.find("timed out") != std::string::npos);
    std::atomic<bool> cancel{false};
    std::thread canceller([&cancel] {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        cancel.store(true);
    });
    start = std::chrono::steady_clock::now();
    CHECK(!detail::command({self, "--ignore-term"}, 10000, &cancel, output, error));
    canceller.join();
    CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(2));
    CHECK(error.find("cancelled") != std::string::npos);
    CHECK(!detail::command({self, "--flood"}, 3000, nullptr, output, error));
    CHECK(output.size() <= 1024 * 1024);
    CHECK(error.find("exceeded") != std::string::npos);
    // No synchronous command leaves live children behind.
    CHECK(waitpid(-1, nullptr, WNOHANG) == -1 && errno == ECHILD);
}

int main(int argc, char **argv) {
    if (argc == 2 && std::strcmp(argv[1], "--ignore-term") == 0) {
        signal(SIGTERM, SIG_IGN);
        for (;;)
            pause();
    }
    if (argc == 2 && std::strcmp(argv[1], "--flood") == 0) {
        std::string bytes(4096, 'x');
        for (unsigned index = 0; index < 512; ++index)
            (void)write(STDOUT_FILENO, bytes.data(), bytes.size());
        return 0;
    }
    char self[PATH_MAX];
    CHECK(realpath(argv[0], self));
    credentials();
    parsing();
    same_network_lease();
    store();
    processes(self);
    BackendConfig config;
    config.interface_name = "wlan0;reboot";
    auto backend = make_linux_backend(config);
    std::string error;
    CHECK(!backend->initialize(error) && !error.empty());
    CHECK(!backend->online());
    puts("Wi-Fi credential vectors, safe storage, scan parsing and bounded child cleanup: PASS");
    return 0;
}
