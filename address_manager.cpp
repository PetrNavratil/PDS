#include "address_manager.h"
#include <iostream>
#include <arpa/inet.h>
#include <cstring>
#include <algorithm>
#include <mutex>


void AddressManager::generate_address_pool(uint32_t pool_start, uint32_t pool_end) {
    uint32_t new_ip = pool_start;
    dhcp_address address;
    struct in_addr addr;
    while(new_ip <= pool_end){
        address.ip = htonl(new_ip);
        available_addresses.push_back(address);
        new_ip++;
    }

    for(const auto &tmp: available_addresses){
        addr.s_addr = tmp.ip;
        cout <<  inet_ntoa(addr) << endl;
    }
}

uint32_t AddressManager::get_address(char *value) {
    struct in_addr addr;
    if(value != NULL ){
        if (inet_aton(value, &addr) != 0) {
            return ntohl(addr.s_addr);
        }
    }
    return 0;
}

uint32_t AddressManager::assign_new_ip_address(uint8_t *mac_address, bool *result) {
    dhcp_address addr;
    addresses_lock.lock();
    if(available_addresses.size() > 0){
        *result = true;
        addr = available_addresses.back();
        available_addresses.pop_back();
        memcpy(&(addr.mac_address), mac_address, 6);
        addr.valid_to = chrono::system_clock::now() + chrono::seconds(BLOCK_OFFER_TIME);
        used_addresses.push_back(addr);
        addresses_lock.unlock();
        return addr.ip;
    } else {
        addresses_lock.unlock();
        *result = false;
        return 0;
    }
}

bool AddressManager::assign_requested_ip_address(uint8_t *mac_address, uint8_t *ip_address) {
    dhcp_address addr;
    uint32_t converted_ip_address;
    memcpy(&converted_ip_address, ip_address, 4);
    vector<dhcp_address>::iterator found_address;
    addresses_lock.lock();
    found_address = find_if(used_addresses.begin(), used_addresses.end(),
        [converted_ip_address](const dhcp_address &m) -> bool {return m.ip == converted_ip_address;});
    if(found_address != used_addresses.end()){
        if(compare_mac_addresses(found_address->mac_address, mac_address)){
            cout << "CAN PROLONG" << endl;
            found_address->valid_to = chrono::system_clock::now() + chrono::seconds(lease_time);
            addresses_lock.unlock();
            return true;
        } else{
            cout << "CANNOT ASSIGN, USED BY SOMEONE ELSE" << endl;
            addresses_lock.unlock();
            return false;
        }
    } else {
        found_address = find_if(available_addresses.begin(), available_addresses.end(),
                                [converted_ip_address](const dhcp_address &m) -> bool {return m.ip == converted_ip_address;});
        if(found_address != available_addresses.end()){
            cout << "FOUND IN AVAILABLE" << endl;
            addr.ip = found_address->ip;
            memcpy(&(addr.mac_address), mac_address, 6);
            addr.valid_to = chrono::system_clock::now() + chrono::milliseconds(lease_time);
            used_addresses.push_back(addr);
            available_addresses.erase(found_address);
            addresses_lock.unlock();
            return true;
        } else {
            cout << "OUT OF RANGE" << endl;
            addresses_lock.unlock();
            return false;
        }
    }
}

bool AddressManager::compare_mac_addresses(uint8_t *mac_a, uint8_t *mac_b){
    for(int i = 0; i < 6; i++){
        if(mac_a[i] != mac_b[i])
            return false;
    }
    return true;
}

uint32_t AddressManager::assign_device_ip() {
    dhcp_address addr = available_addresses.back();
    available_addresses.pop_back();
    return addr.ip;
}

AddressManager::AddressManager(uint32_t lease_time) {
    addresses_lock.unlock();
    this->lease_time = lease_time;
}

void AddressManager::cleaner() {
    std::chrono::system_clock::time_point now;
    while(true){
        addresses_lock.lock();
        now = chrono::system_clock::now();
        used_addresses.erase(remove_if(used_addresses.begin(),
                                  used_addresses.end(),
                                  [&, now](const dhcp_address &m){
            if(m.valid_to <= now){
                dhcp_address address;
                struct in_addr addr;
                addr.s_addr = m.ip;
                address.ip = m.ip;
                cout << "Clearing " << inet_ntoa(addr) << endl;
                this->available_addresses.push_back(address);
                return true;
            }
            return false;
        }), used_addresses.end());
        cout << "SIZES " << available_addresses.size() << " " << used_addresses.size() << endl;
        addresses_lock.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}