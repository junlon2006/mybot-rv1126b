/* SPDX-License-Identifier: Apache-2.0 */
#ifndef RV1126B_WIFI_SERVICE_H
#define RV1126B_WIFI_SERVICE_H

#include "mybot_platform/wifi.h"
#include "wifi_portal.h"
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>

namespace rv1126b_wifi {
/* Private control surface. Injectable backends and short deadlines keep lifecycle
 * tests independent of radio hardware, privileged daemons and real timeouts. */
struct ServiceConfig {
    bool enabled = true;
    bool force_ap = false;
    BackendConfig backend;
};
struct ServiceTiming {
    unsigned connect_budget_ms = 30000;
    unsigned attempt_ms = 15000;
    unsigned submit_grace_ms = 200;
    unsigned finish_grace_ms = 200;
    unsigned success_hold_ms = 5000;
    unsigned scan_interval_ms = 15000;
};
class Service final : public PortalHandler {
  public:
    Service(ServiceConfig config, std::unique_ptr<Backend> backend, std::unique_ptr<Portal> portal,
            std::function<bool()> ready, ServiceTiming timing = {});
    ~Service() override;
    bool start();
    void stop();
    void request_provisioning();
    rv1126b_wifi_status_t snapshot();
    PortalStatus status() override;
    std::vector<AccessPoint> networks() override;
    std::vector<std::string> saved_networks() override;
    bool submit(const std::string &ssid, const std::string &password, std::string &error) override;
    bool saved_action(const std::string &action, unsigned index, const std::string &expected_ssid,
                      std::string &error) override;
    bool finish(std::string &error) override;

  private:
    enum class ActionKind { None, Connect, Delete, SetDefault };
    struct Action {
        ActionKind kind = ActionKind::None;
        Credential credential;
        unsigned index = 0;
    };
    using Clock = std::chrono::steady_clock;
    void run() noexcept;
    void control();
    bool initialize();
    bool enter_ap(const std::string &error = {});
    bool try_saved();
    void connect_candidate(const Credential &credential);
    void mutate_saved(const Action &action);
    void set_state(rv1126b_wifi_state_t state, const std::string &portal_state,
                   const std::string &error = {});
    void cleanup() noexcept;
    void refresh_scan();
    bool stopping() const;

    ServiceConfig config_;
    ServiceTiming timing_;
    std::unique_ptr<Backend> backend_;
    std::unique_ptr<Portal> portal_;
    std::function<bool()> ready_;
    std::mutex mutex_;
    std::condition_variable wake_;
    std::thread worker_;
    std::atomic<bool> stop_{false};
    std::atomic<bool> cancel_attempt_{false};
    rv1126b_wifi_status_t public_status_{};
    PortalStatus portal_status_{"ap", {}, {}, false};
    std::vector<AccessPoint> networks_;
    std::vector<Credential> saved_;
    Action pending_;
    bool busy_ = false;
    bool manual_ = false;
    bool initialized_ = false;
    bool portal_started_ = false;
    bool finish_requested_ = false;
    bool connected_ = false;
    Clock::time_point pending_at_{};
    Clock::time_point finish_at_{};
    Clock::time_point connected_at_{};
    Clock::time_point next_scan_{};
};
bool routed_ipv4_ready(const std::string &interface_name);
} // namespace rv1126b_wifi
#endif
