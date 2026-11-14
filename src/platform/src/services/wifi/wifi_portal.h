/* SPDX-License-Identifier: Apache-2.0 */
#ifndef RV1126B_WIFI_PORTAL_H
#define RV1126B_WIFI_PORTAL_H

#include "wifi_backend.h"
#include <memory>

namespace rv1126b_wifi {
struct PortalStatus {
    std::string state; /* ap, connecting, connected, error */
    std::string error;
    std::string ssid;
    bool concurrent = false;
    bool busy = false;
};
class PortalHandler {
  public:
    virtual ~PortalHandler() = default;
    virtual PortalStatus status() = 0;
    virtual std::vector<AccessPoint> networks() = 0;
    virtual std::vector<std::string> saved_networks() = 0;
    /* Queue work and return promptly: all network mutations run on the control
     * worker. Candidate credentials are persisted only after connection succeeds. */
    virtual bool submit(const std::string &ssid, const std::string &password,
                        std::string &error) = 0;
    virtual bool saved_action(const std::string &action, unsigned index,
                              const std::string &expected_ssid, std::string &error) = 0;
    virtual bool finish(std::string &error) = 0;
};
struct PortalConfig {
    std::string address = "192.168.4.1";
    unsigned short http_port = 80;
    unsigned short dns_port = 53;
};
class Portal {
  public:
    virtual ~Portal() = default;
    virtual bool start(PortalHandler &handler, std::string &error) = 0;
    virtual void stop() = 0;
};
std::unique_ptr<Portal> make_portal(const PortalConfig &config = {});
} // namespace rv1126b_wifi
#endif
