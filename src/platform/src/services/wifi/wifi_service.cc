/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_service.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <ifaddrs.h>
#include <net/if.h>
#include <utility>

namespace rv1126b_wifi {
namespace {
template <size_t N> void bounded_copy(char (&out)[N], const std::string &value) {
    const size_t length = std::min(value.size(), N - 1);
    std::memcpy(out, value.data(), length);
    out[length] = '\0';
}
std::string failure(const std::string &error, const char *fallback) {
    return error.empty() ? fallback : error.substr(0, 159);
}
} // namespace

bool routed_ipv4_ready(const std::string &interface_name) {
    struct ifaddrs *addresses = nullptr;
    if (getifaddrs(&addresses) != 0) {
        return false;
    }
    FILE *routes = std::fopen("/proc/net/route", "r");
    if (!routes) {
        freeifaddrs(addresses);
        return false;
    }
    bool ready = false;
    char line[512];
    while (std::fgets(line, sizeof(line), routes)) {
        char name[IFNAMSIZ];
        unsigned long destination, gateway, flags, mask;
        if (std::sscanf(line, "%15s %lx %lx %lx %*u %*u %*u %lx", name, &destination, &gateway,
                        &flags, &mask) != 5 ||
            destination != 0 || mask != 0 || !(flags & 1UL) || (flags & 0x200UL) ||
            (!interface_name.empty() && interface_name != name)) {
            continue;
        }
        for (const auto *it = addresses; it; it = it->ifa_next) {
            if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET ||
                std::strcmp(it->ifa_name, name) || !(it->ifa_flags & IFF_UP) ||
                !(it->ifa_flags & IFF_RUNNING) || (it->ifa_flags & IFF_LOOPBACK)) {
                continue;
            }
            const auto ip =
                ntohl(reinterpret_cast<const sockaddr_in *>(it->ifa_addr)->sin_addr.s_addr);
            if (ip && (ip >> 24) != 127 && (ip >> 16) != 0xa9fe && (ip >> 28) < 14) {
                ready = true;
                break;
            }
        }
        if (ready) {
            break;
        }
    }
    if (std::ferror(routes)) {
        ready = false;
    }
    std::fclose(routes);
    freeifaddrs(addresses);
    return ready;
}

Service::Service(ServiceConfig config, std::unique_ptr<Backend> backend,
                 std::unique_ptr<Portal> portal, std::function<bool()> ready, ServiceTiming timing)
    : config_(std::move(config)), timing_(timing), backend_(std::move(backend)),
      portal_(std::move(portal)), ready_(std::move(ready)) {
    public_status_.state = RV1126B_WIFI_WAITING;
}
Service::~Service() {
    stop();
}
bool Service::start() {
    if (worker_.joinable() || stopping()) {
        return false;
    }
    try {
        worker_ = std::thread(&Service::run, this);
        return true;
    } catch (...) {
        set_state(RV1126B_WIFI_ERROR, "error", "Cannot start Wi-Fi control worker");
        return false;
    }
}
void Service::stop() {
    stop_.store(true);
    cancel_attempt_.store(true);
    wake_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
}
bool Service::stopping() const {
    return stop_.load();
}
void Service::request_provisioning() {
    if (!config_.enabled || stopping()) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        manual_ = true;
        cancel_attempt_.store(true);
        /* Publish synchronously: the application may decide whether it can
         * restart its SDK immediately after this call returns. */
        public_status_.state = RV1126B_WIFI_WAITING;
        public_status_.error[0] = '\0';
        portal_status_.state = "connecting";
        portal_status_.error.clear();
        connected_ = false;
        finish_requested_ = false;
        pending_ = {};
        busy_ = true;
    }
    wake_.notify_all();
}
rv1126b_wifi_status_t Service::snapshot() {
    std::lock_guard<std::mutex> lock(mutex_);
    return public_status_;
}
PortalStatus Service::status() {
    std::lock_guard<std::mutex> lock(mutex_);
    auto result = portal_status_;
    result.busy = busy_;
    return result;
}
std::vector<AccessPoint> Service::networks() {
    std::lock_guard<std::mutex> lock(mutex_);
    return networks_;
}
std::vector<std::string> Service::saved_networks() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> names;
    for (const auto &credential : saved_) {
        names.push_back(credential.ssid);
    }
    return names;
}
bool Service::submit(const std::string &ssid, const std::string &password, std::string &error) {
    Credential credential;
    if (!make_credential(ssid, password, credential, error)) {
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping() || manual_ || !portal_started_ || connected_ || busy_) {
            error = "Wi-Fi control is busy";
            return false;
        }
        pending_ = {ActionKind::Connect, std::move(credential), 0};
        /* Leave time for the HTTP 202 response to reach the browser before a
         * single-interface radio must leave AP mode to attempt station mode. */
        pending_at_ = Clock::now() + std::chrono::milliseconds(timing_.submit_grace_ms);
        busy_ = true;
        public_status_.state = RV1126B_WIFI_CONNECTING;
        public_status_.error[0] = '\0';
        portal_status_.state = "connecting";
        portal_status_.error.clear();
    }
    wake_.notify_all();
    return true;
}
bool Service::saved_action(const std::string &action, unsigned index,
                           const std::string &expected_ssid, std::string &error) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (action != "delete" && action != "set_default") {
            error = "Unknown saved network action";
            return false;
        }
        if (stopping() || manual_ || !portal_started_ || connected_ || busy_) {
            error = "Wi-Fi control is busy";
            return false;
        }
        if (index >= saved_.size()) {
            error = "Saved network does not exist";
            return false;
        }
        if (saved_[index].ssid != expected_ssid) {
            error = "Saved network list changed; refresh and retry";
            return false;
        }
        pending_.kind = action == "delete" ? ActionKind::Delete : ActionKind::SetDefault;
        pending_.index = index;
        busy_ = true;
    }
    wake_.notify_all();
    return true;
}
bool Service::finish(std::string &error) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping() || !connected_) {
            error = "Wi-Fi is not connected";
            return false;
        }
        if (!finish_requested_) {
            finish_requested_ = true;
            finish_at_ = Clock::now() + std::chrono::milliseconds(timing_.finish_grace_ms);
        }
    }
    wake_.notify_all();
    return true;
}
void Service::set_state(rv1126b_wifi_state_t state, const std::string &portal_state,
                        const std::string &error) {
    std::lock_guard<std::mutex> lock(mutex_);
    /* A pending manual request owns the next transition. A previous startup or
     * portal-close operation must not republish ONLINE after that request. */
    if (manual_ && state == RV1126B_WIFI_ONLINE) {
        return;
    }
    public_status_.state = state;
    bounded_copy(public_status_.error, error);
    portal_status_.state = portal_state;
    portal_status_.error = error.substr(0, 159);
}
bool Service::initialize() {
    if (initialized_) {
        return true;
    }
    std::string error;
    if (!backend_ || !portal_ || !backend_->initialize(error)) {
        set_state(RV1126B_WIFI_ERROR, "error", failure(error, "Wi-Fi backend is unavailable"));
        return false;
    }
    initialized_ = true;
    auto credentials = backend_->load(error);
    /* The backend validates profiles on disk. Bound our cache independently. */
    if (credentials.size() > 10) {
        credentials.resize(10);
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        saved_ = std::move(credentials);
        portal_status_.concurrent = backend_->concurrent_ap();
    }
    return true;
}
bool Service::enter_ap(const std::string &previous_error) {
    if (stopping() || cancel_attempt_.load()) {
        return false;
    }
    std::string error;
    if (!backend_->start_ap(error) || !backend_->ap_running()) {
        if (portal_started_) {
            portal_->stop();
        }
        backend_->stop_ap();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            portal_started_ = false;
            public_status_.ap_active = false;
            busy_ = false;
        }
        set_state(RV1126B_WIFI_ERROR, "error", failure(error, "Wi-Fi access point did not start"));
        return false;
    }
    bool already_started;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        already_started = portal_started_;
    }
    if (!already_started && !portal_->start(*this, error)) {
        portal_->stop();
        backend_->stop_ap();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            portal_started_ = false;
            public_status_.ap_active = false;
            busy_ = false;
        }
        set_state(RV1126B_WIFI_ERROR, "error", failure(error, "Wi-Fi setup portal did not start"));
        return false;
    }
    const auto ssid = backend_->ap_ssid();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        portal_started_ = true;
        public_status_.ap_active = true;
        bounded_copy(public_status_.ssid, ssid);
        portal_status_.ssid = ssid;
        portal_status_.concurrent = backend_->concurrent_ap();
        busy_ = false;
        connected_ = false;
        finish_requested_ = false;
    }
    set_state(RV1126B_WIFI_AP_READY, previous_error.empty() ? "ap" : "error", previous_error);
    next_scan_ = Clock::now();
    return true;
}
bool Service::try_saved() {
    std::vector<Credential> credentials;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        credentials = saved_;
    }
    const auto deadline = Clock::now() + std::chrono::milliseconds(timing_.connect_budget_ms);
    for (size_t i = 0; i < credentials.size() && !stopping() && !cancel_attempt_.load(); ++i) {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        if (remaining <= 0) {
            break;
        }
        const auto fair = static_cast<unsigned>(remaining / (credentials.size() - i));
        const auto timeout = std::min(timing_.attempt_ms, std::max(1U, fair));
        set_state(RV1126B_WIFI_CONNECTING, "connecting");
        std::string error;
        if (backend_->connect(credentials[i], timeout, cancel_attempt_, error) && !stopping() &&
            !cancel_attempt_.load() && backend_->online()) {
            set_state(RV1126B_WIFI_ONLINE, "connected");
            return true;
        }
    }
    return false;
}
void Service::connect_candidate(const Credential &credential) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(timing_.connect_budget_ms);
    std::string error;
    bool connected = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!backend_->concurrent_ap()) {
            public_status_.ap_active = false;
        }
    }
    for (unsigned attempt = 0; attempt < 2 && !stopping() && !cancel_attempt_.load(); ++attempt) {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        if (remaining <= 0) {
            break;
        }
        const unsigned timeout = std::min(timing_.attempt_ms, static_cast<unsigned>(remaining));
        if (backend_->connect(credential, timeout, cancel_attempt_, error) && !stopping() &&
            !cancel_attempt_.load() && backend_->online()) {
            connected = true;
            break;
        }
    }
    if (stopping() || cancel_attempt_.load()) {
        return;
    }
    if (!connected) {
        enter_ap(failure(error, "Wi-Fi connection failed; check the network and password"));
        return;
    }
    std::vector<Credential> updated;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        updated = saved_;
    }
    updated.erase(
        std::remove_if(updated.begin(), updated.end(),
                       [&](const Credential &item) { return item.ssid == credential.ssid; }),
        updated.end());
    updated.insert(updated.begin(), credential);
    if (updated.size() > 10) {
        updated.resize(10);
    }
    error.clear();
    if (!backend_->save(updated, error)) {
        /* A usable route alone does not complete provisioning: the profile
         * must survive a restart. Retain the previous saved cache and restore
         * the setup AP so the user can retry rather than showing success. */
        enter_ap(failure(error, "Network could not be saved; please retry"));
        return;
    }
    const bool ap_active = backend_->ap_running();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        saved_ = std::move(updated);
        public_status_.ap_active = ap_active;
        connected_ = true;
        busy_ = false;
        connected_at_ = Clock::now();
        finish_requested_ = false;
    }
    set_state(RV1126B_WIFI_VERIFYING, "connected");
}
void Service::mutate_saved(const Action &action) {
    std::vector<Credential> updated;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        updated = saved_;
    }
    if (action.index >= updated.size()) {
        std::lock_guard<std::mutex> lock(mutex_);
        busy_ = false;
        return;
    }
    if (action.kind == ActionKind::Delete) {
        updated.erase(updated.begin() + action.index);
    } else {
        auto credential = updated[action.index];
        updated.erase(updated.begin() + action.index);
        updated.insert(updated.begin(), std::move(credential));
    }
    std::string error;
    const bool saved = backend_->save(updated, error);
    const auto result_error =
        saved ? std::string{} : failure(error, "Saved networks could not be updated");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (saved) {
            saved_ = std::move(updated);
        }
        /* Publish completion and its result together. The browser polls busy
         * before reading the saved list or reporting a persistence failure. */
        public_status_.state = RV1126B_WIFI_AP_READY;
        bounded_copy(public_status_.error, result_error);
        portal_status_.state = saved ? "ap" : "error";
        portal_status_.error = result_error;
        busy_ = false;
    }
}
void Service::refresh_scan() {
    std::string error;
    auto networks = backend_->scan(error);
    if (networks.size() > 64) {
        networks.resize(64);
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        networks_ = std::move(networks);
    }
    next_scan_ = Clock::now() + std::chrono::milliseconds(timing_.scan_interval_ms);
}
void Service::control() {
    if (!config_.enabled) {
        while (!stopping()) {
            set_state(ready_ && ready_() ? RV1126B_WIFI_ONLINE : RV1126B_WIFI_WAITING, "ap");
            std::unique_lock<std::mutex> lock(mutex_);
            wake_.wait_for(lock, std::chrono::milliseconds(250), [&] { return stopping(); });
        }
        return;
    }
    if (!config_.force_ap && ready_ && ready_()) {
        set_state(RV1126B_WIFI_ONLINE, "connected");
    } else if (initialize()) {
        if (config_.force_ap || !try_saved()) {
            enter_ap();
        }
    }
    while (!stopping()) {
        Action action;
        bool manual = false;
        bool finish = false;
        bool scan = false;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            const auto now = Clock::now();
            if (manual_) {
                manual_ = false;
                manual = true;
                pending_ = {};
                busy_ = false;
                connected_ = false;
                finish_requested_ = false;
                portal_status_.error.clear();
                public_status_.error[0] = '\0';
            } else if (pending_.kind != ActionKind::None) {
                if (pending_.kind == ActionKind::Connect && now < pending_at_) {
                    wake_.wait_until(lock, pending_at_);
                    continue;
                }
                action = std::move(pending_);
                pending_ = {};
            } else if (connected_ &&
                       (finish_requested_ ? now >= finish_at_
                                          : now >= connected_at_ + std::chrono::milliseconds(
                                                                       timing_.success_hold_ms))) {
                connected_ = false;
                finish = true;
            } else if (portal_started_ && !connected_ && !busy_ && now >= next_scan_) {
                scan = true;
            } else {
                wake_.wait_for(lock, std::chrono::milliseconds(50));
                continue;
            }
        }
        if (manual) {
            cancel_attempt_.store(false);
            if (initialize()) {
                enter_ap();
            }
        } else if (action.kind == ActionKind::Connect) {
            connect_candidate(action.credential);
        } else if (action.kind != ActionKind::None) {
            mutate_saved(action);
        } else if (finish) {
            portal_->stop();
            backend_->stop_ap();
            {
                std::lock_guard<std::mutex> lock(mutex_);
                portal_started_ = false;
                public_status_.ap_active = false;
                busy_ = false;
            }
            set_state(RV1126B_WIFI_ONLINE, "connected");
        } else if (scan) {
            refresh_scan();
        }
    }
}
void Service::cleanup() noexcept {
    try {
        if (config_.enabled && portal_ && initialized_) {
            portal_->stop();
        }
    } catch (...) {
    }
    try {
        if (initialized_) {
            backend_->stop_ap();
        }
    } catch (...) {
    }
    std::lock_guard<std::mutex> lock(mutex_);
    portal_started_ = false;
    public_status_.ap_active = false;
    busy_ = false;
    pending_ = {};
}
void Service::run() noexcept {
    try {
        control();
    } catch (...) {
        set_state(RV1126B_WIFI_ERROR, "error", "Wi-Fi service failed");
    }
    cleanup();
}
} // namespace rv1126b_wifi

namespace {
std::mutex service_mutex;
std::unique_ptr<rv1126b_wifi::Service> service;
} // namespace
extern "C" int rv1126b_wifi_start(const rv1126b_wifi_config_t *config) {
    try {
        if (!config) {
            return -1;
        }
        std::lock_guard<std::mutex> lock(service_mutex);
        if (service) {
            return -1;
        }
        rv1126b_wifi::ServiceConfig owned;
        owned.enabled = config->enabled;
        owned.force_ap = config->force_ap;
        owned.backend.interface_name = config->interface_name ? config->interface_name : "";
        owned.backend.storage_directory =
            config->storage_directory ? config->storage_directory : "";
        owned.backend.runtime_directory =
            config->runtime_directory ? config->runtime_directory : "";
        owned.backend.dhcp_script = config->dhcp_script ? config->dhcp_script : "";
        const auto interface = owned.backend.interface_name;
        auto backend = owned.enabled ? rv1126b_wifi::make_linux_backend(owned.backend) : nullptr;
        auto portal = owned.enabled ? rv1126b_wifi::make_portal() : nullptr;
        auto candidate = std::make_unique<rv1126b_wifi::Service>(
            std::move(owned), std::move(backend), std::move(portal),
            [interface] { return rv1126b_wifi::routed_ipv4_ready(interface); });
        if (!candidate->start()) {
            return -1;
        }
        service = std::move(candidate);
        return 0;
    } catch (...) {
        return -1;
    }
}
extern "C" void rv1126b_wifi_request_provisioning(void) {
    try {
        std::lock_guard<std::mutex> lock(service_mutex);
        if (service) {
            service->request_provisioning();
        }
    } catch (...) {
    }
}
extern "C" void rv1126b_wifi_status(rv1126b_wifi_status_t *status) {
    if (!status) {
        return;
    }
    *status = {};
    status->state = RV1126B_WIFI_WAITING;
    try {
        std::lock_guard<std::mutex> lock(service_mutex);
        if (service) {
            *status = service->snapshot();
        }
    } catch (...) {
        status->state = RV1126B_WIFI_ERROR;
    }
}
extern "C" void rv1126b_wifi_stop(void) {
    try {
        std::lock_guard<std::mutex> lock(service_mutex);
        if (service) {
            service->stop();
            service.reset();
        }
    } catch (...) {
    }
}
