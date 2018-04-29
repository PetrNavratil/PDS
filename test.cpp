//
// Created by isa2015 on 17.4.18.
//
#include "packet-manager.h"
int main(int argc, char* argv[]) {
    uint8_t fake[] = {0xdc, 0xa1, 0xb9, 0x45, 0x9e, 0x0d};
    PacketManager p;
    p.preparePacket(PACKET_DISCOVER);
    p.insertSendMacAddress(&fake[0]);
    p.getPacketSize();
    p.printPacket();
    p.computeSizes();
    p.computeCheckSum();
}