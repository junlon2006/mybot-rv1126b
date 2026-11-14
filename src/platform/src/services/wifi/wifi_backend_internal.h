/* SPDX-License-Identifier: Apache-2.0 */
#ifndef RV1126B_WIFI_BACKEND_INTERNAL_H
#define RV1126B_WIFI_BACKEND_INTERNAL_H

#include "wifi_backend.h"
#include <sys/types.h>

namespace rv1126b_wifi {
namespace detail {
bool valid_interface(const std::string &name);
bool valid_ssid(const std::string &ssid);
std::string encode_hex(const std::string &value);
bool decode_hex(const std::string &value, std::string &decoded);
bool decode_wpa_string(const std::string &value, std::string &decoded);
std::vector<AccessPoint> parse_scan_results(const std::string &text);
int frequency_channel(int frequency);
/* Reuse only a pre-existing lease proven to belong to the same completed AP association. */
bool same_association_lease(const std::string &initial_status, const std::string &current_status,
                            const std::string &requested_ssid, const std::string &trial_id,
                            const std::string &initial_route, const std::string &current_route);
bool read_credentials(int directory, std::vector<Credential> &credentials, std::string &error);
bool write_credentials(int directory, const std::vector<Credential> &credentials,
                       std::string &error);
/* Shell-free, bounded helper; output is limited and credentials never use argv. */
bool command(const std::vector<std::string> &arguments, unsigned timeout_ms,
             const std::atomic<bool> *cancel, std::string &output, std::string &error);
} // namespace detail
} // namespace rv1126b_wifi
#endif
