/* SPDX-License-Identifier: Apache-2.0 */
#ifndef RV1126B_WIFI_BACKEND_H
#define RV1126B_WIFI_BACKEND_H

#include <atomic>
#include <memory>
#include <string>
#include <vector>

namespace rv1126b_wifi {

struct Credential {
    std::string ssid;
    std::string psk; /* Empty for open Wi-Fi; otherwise a derived 64-digit PSK. */
};
struct AccessPoint {
    std::string ssid;
    int rssi = -100;
    int authmode = 0;
    int channel = 0;
};
struct BackendConfig {
    std::string interface_name;
    std::string storage_directory;
    std::string runtime_directory;
    std::string dhcp_script;
};

bool make_credential(const std::string &ssid, const std::string &password, Credential &credential,
                     std::string &error);

class Backend {
  public:
    virtual ~Backend() = default;
    virtual bool initialize(std::string &error) = 0;
    virtual std::string ap_ssid() const = 0;
    virtual bool start_ap(std::string &error) = 0;
    virtual void stop_ap() = 0;
    virtual bool ap_running() = 0;
    virtual bool concurrent_ap() const = 0;
    virtual bool online() const = 0;
    virtual std::vector<AccessPoint> scan(std::string &error) = 0;
    virtual std::vector<Credential> load(std::string &error) = 0;
    virtual bool save(const std::vector<Credential> &credentials, std::string &error) = 0;
    /* Success requires a usable routed IPv4 address, not association alone.
     * Cancel must bound shutdown; this method runs only on the control worker. */
    virtual bool connect(const Credential &credential, unsigned timeout_ms,
                         const std::atomic<bool> &cancel, std::string &error) = 0;
};

std::unique_ptr<Backend> make_linux_backend(const BackendConfig &config);
} // namespace rv1126b_wifi
#endif
