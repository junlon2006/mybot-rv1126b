/* SPDX-License-Identifier: Apache-2.0 */
#include "check.h"
#include "wifi_service.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <thread>

using namespace rv1126b_wifi;
using namespace std::chrono_literals;
namespace {
struct FakeState {
    std::atomic<unsigned> initialized{0}, ap_starts{0}, ap_stops{0}, connections{0}, saves{0};
    std::atomic<unsigned> portal_starts{0}, portal_stops{0}, scans{0};
    std::atomic<bool> ap{false}, initialize_ok{true}, ap_ok{true}, portal_ok{true};
    std::atomic<bool> connection_ok{false}, routed{true}, concurrent{true};
    std::atomic<bool> block_connect{false}, block_save{false}, save_ok{true};
    std::atomic<bool> block_portal_stop{false};
    std::atomic<bool> throws{false}, wrong_thread{false};
    std::mutex mutex;
    std::vector<Credential> disk;
    std::vector<Credential> attempted;
    std::vector<unsigned> timeouts;
    std::thread::id owner;
    void owned() {
        std::lock_guard<std::mutex> lock(mutex);
        if (owner == std::thread::id{}) {
            owner = std::this_thread::get_id();
        } else if (owner != std::this_thread::get_id()) {
            wrong_thread = true;
        }
    }
};
class FakeBackend final : public Backend {
  public:
    explicit FakeBackend(std::shared_ptr<FakeState> state) : state_(std::move(state)) {
    }
    bool initialize(std::string &error) override {
        state_->owned();
        ++state_->initialized;
        if (state_->throws) {
            throw std::runtime_error("injected failure");
        }
        error = state_->initialize_ok ? "" : "Missing AP tools";
        return state_->initialize_ok;
    }
    std::string ap_ssid() const override {
        return "mybot-test";
    }
    bool start_ap(std::string &error) override {
        state_->owned();
        ++state_->ap_starts;
        state_->ap = state_->ap_ok.load();
        error = state_->ap_ok ? "" : "Access point failure";
        return state_->ap_ok;
    }
    void stop_ap() override {
        state_->owned();
        ++state_->ap_stops;
        state_->ap = false;
    }
    bool ap_running() override {
        return state_->ap;
    }
    bool concurrent_ap() const override {
        return state_->concurrent;
    }
    bool online() const override {
        return state_->routed;
    }
    std::vector<AccessPoint> scan(std::string &) override {
        state_->owned();
        ++state_->scans;
        return {{"test-network", -50, 3, 6}};
    }
    std::vector<Credential> load(std::string &) override {
        state_->owned();
        std::lock_guard<std::mutex> lock(state_->mutex);
        return state_->disk;
    }
    bool save(const std::vector<Credential> &credentials, std::string &error) override {
        state_->owned();
        ++state_->saves;
        while (state_->block_save) {
            std::this_thread::sleep_for(1ms);
        }
        if (!state_->save_ok) {
            error = "Cannot persist network";
            return false;
        }
        std::lock_guard<std::mutex> lock(state_->mutex);
        state_->disk = credentials;
        return true;
    }
    bool connect(const Credential &credential, unsigned timeout, const std::atomic<bool> &cancel,
                 std::string &error) override {
        state_->owned();
        ++state_->connections;
        if (!state_->concurrent) {
            state_->ap = false;
        }
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            state_->attempted.push_back(credential);
            state_->timeouts.push_back(timeout);
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
        while (state_->block_connect && !cancel && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(1ms);
        }
        if (cancel) {
            error = "Cancelled";
            return false;
        }
        error = state_->connection_ok ? "" : "Connection failed";
        return state_->connection_ok;
    }

  private:
    std::shared_ptr<FakeState> state_;
};
class FakePortal final : public Portal {
  public:
    explicit FakePortal(std::shared_ptr<FakeState> state) : state_(std::move(state)) {
    }
    bool start(PortalHandler &, std::string &error) override {
        state_->owned();
        ++state_->portal_starts;
        error = state_->portal_ok ? "" : "HTTP/DNS bind failed";
        return state_->portal_ok;
    }
    void stop() override {
        state_->owned();
        ++state_->portal_stops;
        while (state_->block_portal_stop) {
            std::this_thread::sleep_for(1ms);
        }
    }

  private:
    std::shared_ptr<FakeState> state_;
};
void await(const std::function<bool()> &ready) {
    const auto deadline = std::chrono::steady_clock::now() + 1500ms;
    while (!ready() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(1ms);
    }
    CHECK(ready());
}
ServiceTiming timing() {
    ServiceTiming value;
    value.connect_budget_ms = 60;
    value.attempt_ms = 30;
    value.submit_grace_ms = 5;
    value.finish_grace_ms = 20;
    value.success_hold_ms = 1000;
    value.scan_interval_ms = 1000;
    return value;
}
std::unique_ptr<Service> make_service(const std::shared_ptr<FakeState> &state,
                                      ServiceConfig config = {}, bool ready = false,
                                      ServiceTiming deadlines = timing()) {
    return std::make_unique<Service>(
        config, std::make_unique<FakeBackend>(state), std::make_unique<FakePortal>(state),
        [ready] { return ready; }, deadlines);
}
Credential profile(const std::string &ssid) {
    return {ssid, std::string(64, 'a')};
}
void wait_ap(Service &service) {
    await([&] { return service.snapshot().state == RV1126B_WIFI_AP_READY; });
    CHECK(service.snapshot().ap_active);
    CHECK(std::string(service.snapshot().ssid) == "mybot-test");
}
void test_disabled_and_existing_network() {
    auto state = std::make_shared<FakeState>();
    ServiceConfig disabled;
    disabled.enabled = false;
    auto service = make_service(state, disabled, true);
    CHECK(service->start());
    await([&] { return service->snapshot().state == RV1126B_WIFI_ONLINE; });
    service->request_provisioning();
    service->stop();
    CHECK(!state->initialized && !state->ap_starts && !state->portal_starts);
    CHECK(!state->ap_stops && !state->portal_stops);

    state = std::make_shared<FakeState>();
    state->initialize_ok = false;
    service = make_service(state, {}, true);
    CHECK(service->start());
    await([&] { return service->snapshot().state == RV1126B_WIFI_ONLINE; });
    CHECK(!state->initialized);
    state->initialize_ok = true;
    service->request_provisioning();
    CHECK(service->snapshot().state != RV1126B_WIFI_ONLINE);
    wait_ap(*service);
    CHECK(state->initialized == 1);
    CHECK(!state->wrong_thread);
}
void test_ap_and_portal_rollback() {
    for (bool portal_failure : {false, true}) {
        auto state = std::make_shared<FakeState>();
        state->ap_ok = portal_failure;
        state->portal_ok = false;
        auto service = make_service(state);
        CHECK(service->start());
        await([&] { return service->snapshot().state == RV1126B_WIFI_ERROR; });
        CHECK(!service->snapshot().ap_active);
        CHECK(state->portal_starts == (portal_failure ? 1U : 0U));
        CHECK(state->ap_stops >= 1);
        CHECK(!state->ap);
    }
    auto state = std::make_shared<FakeState>();
    state->throws = true;
    auto service = make_service(state);
    CHECK(service->start());
    await([&] { return service->snapshot().state == RV1126B_WIFI_ERROR; });
    CHECK(!service->snapshot().ap_active);
}
void test_saved_attempts_and_deadline() {
    auto state = std::make_shared<FakeState>();
    state->disk = {profile("one"), profile("two"), profile("three")};
    state->block_connect = true;
    auto service = make_service(state);
    const auto before = std::chrono::steady_clock::now();
    CHECK(service->start());
    wait_ap(*service);
    CHECK(state->connections == 3);
    CHECK(std::chrono::steady_clock::now() - before < 250ms);
    CHECK(!state->saves);
    CHECK(!state->wrong_thread);

    state = std::make_shared<FakeState>();
    state->disk = {profile("known")};
    state->connection_ok = true;
    service = make_service(state);
    CHECK(service->start());
    await([&] { return service->snapshot().state == RV1126B_WIFI_ONLINE; });
    CHECK(state->connections == 1 && !state->ap_starts && !state->portal_starts);
}
void test_candidate_failure_then_success_and_grace() {
    auto state = std::make_shared<FakeState>();
    auto service = make_service(state);
    CHECK(service->start());
    wait_ap(*service);
    await([&] { return !service->networks().empty(); });
    std::string error;
    CHECK(!service->submit("test", "short", error));
    CHECK(!state->connections);
    CHECK(service->submit("test", "password123", error));
    await([&] { return state->connections == 2; });
    wait_ap(*service);
    CHECK(service->status().state == "error");
    CHECK(!state->saves);
    state->connection_ok = true;
    CHECK(service->submit("test", "password123", error));
    await([&] { return service->status().state == "connected"; });
    CHECK(service->snapshot().state == RV1126B_WIFI_VERIFYING);
    CHECK(service->snapshot().ap_active);
    CHECK(state->saves == 1);
    CHECK(!service->submit("other", "password123", error));
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        CHECK(state->disk.size() == 1 && state->disk.front().ssid == "test");
        CHECK(state->disk.front().psk.size() == 64);
        CHECK(state->disk.front().psk != "password123");
    }
    const auto before = std::chrono::steady_clock::now();
    CHECK(service->finish(error));
    CHECK(service->snapshot().ap_active);
    await([&] { return service->snapshot().state == RV1126B_WIFI_ONLINE; });
    CHECK(std::chrono::steady_clock::now() - before >= 20ms);
    CHECK(!service->snapshot().ap_active);
    service->request_provisioning();
    CHECK(service->snapshot().state != RV1126B_WIFI_ONLINE);
    wait_ap(*service);
    CHECK(service->status().state == "ap");
    CHECK(service->status().error.empty());
    CHECK(!service->finish(error));
    CHECK(!state->wrong_thread);
}
void test_requires_routed_ip_and_single_interface_recovery() {
    auto state = std::make_shared<FakeState>();
    state->concurrent = false;
    state->connection_ok = true;
    state->routed = false;
    auto service = make_service(state);
    CHECK(service->start());
    wait_ap(*service);
    std::string error;
    CHECK(service->submit("test", "password123", error));
    await([&] { return state->connections == 2; });
    wait_ap(*service);
    CHECK(state->ap_starts == 2);
    CHECK(state->portal_starts == 1);
    CHECK(!state->saves);
    state->routed = true;
    CHECK(service->submit("test", "password123", error));
    await([&] { return service->status().state == "connected"; });
    CHECK(!service->snapshot().ap_active);
}
void test_saved_mutations_and_mru() {
    auto state = std::make_shared<FakeState>();
    for (int i = 0; i < 10; ++i) {
        state->disk.push_back(profile("network-" + std::to_string(i)));
    }
    ServiceConfig config;
    config.force_ap = true;
    auto service = make_service(state, config, true);
    CHECK(service->start());
    wait_ap(*service);
    CHECK(!state->connections);
    std::string error;
    CHECK(!service->saved_action("delete", 10, "missing", error));
    CHECK(!service->saved_action("unknown", 0, "network-0", error));
    state->block_save = true;
    CHECK(service->saved_action("set_default", 4, "network-4", error));
    await([&] { return state->saves == 1; });
    CHECK(service->status().busy);
    CHECK(service->saved_networks().front() == "network-0");
    CHECK(!service->saved_action("delete", 0, "network-0", error));
    CHECK(!service->submit("new", "password123", error));
    state->block_save = false;
    await([&] { return service->saved_networks().front() == "network-4"; });
    CHECK(!service->status().busy && service->status().state == "ap");
    CHECK(!service->saved_action("delete", 0, "network-0", error));
    CHECK(!service->saved_action("set_default", 0, "network-0", error));
    CHECK(service->saved_networks().front() == "network-4");
    CHECK(service->saved_networks().size() == 10 && state->saves == 1);
    CHECK(service->saved_action("delete", 0, "network-4", error));
    await([&] { return service->saved_networks().size() == 9; });
    state->connection_ok = true;
    CHECK(service->submit("new", "password123", error));
    await([&] { return service->status().state == "connected"; });
    CHECK(service->saved_networks().size() == 10);
    CHECK(service->saved_networks().front() == "new");
    CHECK(service->finish(error));
    await([&] { return service->snapshot().state == RV1126B_WIFI_ONLINE; });
    service->request_provisioning();
    CHECK(service->snapshot().state != RV1126B_WIFI_ONLINE);
    wait_ap(*service);
    CHECK(service->submit("network-7", "password456", error));
    await([&] { return service->status().state == "connected"; });
    const auto names = service->saved_networks();
    CHECK(names.size() == 10 && names.front() == "network-7");
    CHECK(std::count(names.begin(), names.end(), "network-7") == 1);
}
void test_stop_cancels_and_auto_finish() {
    auto state = std::make_shared<FakeState>();
    state->block_connect = true;
    auto service = make_service(state);
    CHECK(service->start());
    wait_ap(*service);
    std::string error;
    CHECK(service->submit("test", "password123", error));
    await([&] { return state->connections == 1; });
    const auto before = std::chrono::steady_clock::now();
    service->stop();
    CHECK(std::chrono::steady_clock::now() - before < 100ms);
    CHECK(!service->snapshot().ap_active);
    CHECK(!state->saves);
    CHECK(!service->submit("test", "password123", error));
    CHECK(!service->saved_action("delete", 0, "test", error));

    state = std::make_shared<FakeState>();
    state->connection_ok = true;
    auto deadlines = timing();
    deadlines.success_hold_ms = 30;
    service = make_service(state, {}, false, deadlines);
    CHECK(service->start());
    wait_ap(*service);
    CHECK(service->submit("test", "password123", error));
    await([&] { return service->snapshot().state == RV1126B_WIFI_ONLINE; });
    CHECK(!service->snapshot().ap_active);
}
void test_manual_request_during_close_and_late_finish() {
    auto state = std::make_shared<FakeState>();
    state->connection_ok = true;
    auto service = make_service(state);
    CHECK(service->start());
    wait_ap(*service);
    std::string error;
    CHECK(service->submit("test", "password123", error));
    await([&] { return service->status().state == "connected"; });
    state->block_portal_stop = true;
    CHECK(service->finish(error));
    await([&] { return state->portal_stops == 1; });
    service->request_provisioning();
    CHECK(service->snapshot().state == RV1126B_WIFI_WAITING);
    state->block_portal_stop = false;
    await([&] {
        CHECK(service->snapshot().state != RV1126B_WIFI_ONLINE);
        return service->snapshot().state == RV1126B_WIFI_AP_READY;
    });

    state = std::make_shared<FakeState>();
    state->connection_ok = true;
    auto deadlines = timing();
    deadlines.success_hold_ms = 20;
    deadlines.finish_grace_ms = 40;
    service = make_service(state, {}, false, deadlines);
    CHECK(service->start());
    wait_ap(*service);
    CHECK(service->submit("test", "password123", error));
    await([&] { return service->status().state == "connected"; });
    const auto before = std::chrono::steady_clock::now();
    CHECK(service->finish(error));
    await([&] { return service->snapshot().state == RV1126B_WIFI_ONLINE; });
    CHECK(std::chrono::steady_clock::now() - before >= 40ms);
}
void test_failed_persistence_does_not_change_cache() {
    auto state = std::make_shared<FakeState>();
    state->disk = {profile("old")};
    state->save_ok = false;
    ServiceConfig config;
    config.force_ap = true;
    auto service = make_service(state, config);
    CHECK(service->start());
    wait_ap(*service);
    std::string error;
    state->block_save = true;
    CHECK(service->saved_action("delete", 0, "old", error));
    await([&] { return state->saves == 1; });
    CHECK(service->status().busy);
    CHECK(service->saved_networks().size() == 1);
    state->block_save = false;
    await([&] { return !service->status().busy; });
    CHECK(service->status().state == "error");
    CHECK(!service->status().error.empty());
    CHECK(std::string(service->snapshot().error) == service->status().error);
    CHECK(service->saved_networks().size() == 1);
    state->connection_ok = true;
    CHECK(service->submit("new", "password123", error));
    await([&] {
        return service->snapshot().state == RV1126B_WIFI_AP_READY &&
               service->status().state == "error";
    });
    CHECK(service->snapshot().ap_active);
    CHECK(service->saved_networks().front() == "old");
    CHECK(!service->status().error.empty());
    CHECK(!service->finish(error));
    state->save_ok = true;
    CHECK(service->submit("new", "password123", error));
    await([&] { return service->status().state == "connected"; });
    CHECK(service->saved_networks().front() == "new");
    CHECK(service->status().error.empty());
    CHECK(service->finish(error));
}
} // namespace
int main() {
    test_disabled_and_existing_network();
    test_ap_and_portal_rollback();
    test_saved_attempts_and_deadline();
    test_candidate_failure_then_success_and_grace();
    test_requires_routed_ip_and_single_interface_recovery();
    test_saved_mutations_and_mru();
    test_stop_cancels_and_auto_finish();
    test_failed_persistence_does_not_change_cache();
    test_manual_request_during_close_and_late_finish();
    CHECK(rv1126b_wifi_start(nullptr) == -1);
    rv1126b_wifi_config_t disabled{};
    CHECK(rv1126b_wifi_start(&disabled) == 0);
    CHECK(rv1126b_wifi_start(&disabled) == -1);
    rv1126b_wifi_request_provisioning();
    rv1126b_wifi_status(nullptr);
    rv1126b_wifi_stop();
    rv1126b_wifi_stop();
    rv1126b_wifi_status_t stopped{};
    rv1126b_wifi_status(&stopped);
    CHECK(stopped.state == RV1126B_WIFI_WAITING && !stopped.ap_active);
    return 0;
}
