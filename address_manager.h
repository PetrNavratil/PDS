//
// Created by isa2015 on 22.4.18.
//

#include <vector>
#include <chrono>
#include <unistd.h>
#include <mutex>
#include <thread>

#ifndef PDS_ADDRESS_MANAGER_H
#define PDS_ADDRESS_MANAGER_H

#define BLOCK_OFFER_TIME 30

using namespace std;

struct dhcp_address{
    uint32_t ip;
    uint8_t mac_address[6];
    std::chrono::system_clock::time_point valid_to;
};

class AddressManager{
private:
    bool compare_mac_addresses(uint8_t *mac_a, uint8_t *mac_b);
    uint32_t lease_time;
public:
    mutex addresses_lock;
    vector<dhcp_address> available_addresses;
    vector<dhcp_address> used_addresses;
    void generate_address_pool(uint32_t pool_start, uint32_t pool_end);
    uint32_t assign_new_ip_address(uint8_t *mac_address, bool *result);
    uint32_t assign_device_ip();
    bool assign_requested_ip_address(uint8_t *mac_address, uint8_t *ip_address);
    static uint32_t get_address(char *value);
    AddressManager(uint32_t lease_time);
    void cleaner();
};

#endif //PDS_ADDRESS_MANAGER_H
