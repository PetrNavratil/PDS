xnavra53@stud.fit.vutbr.cz
PDS 2017/2018

DHCP-STARVATION
Aplikace provadi cely DORA utok na vsechny DHCP servery v siti
Prodleva mezi odesilanim packetu je 0.2s
Spusteni: ./pds-dhcpstarve -i eth0

DHCP-ROGUE
Aplikace provadi funkcnost falesneho DHCP serveru
Paralelne prijima a odpovida na dotazy
Spusteni: ./pds-dhcprogue -l 120 -n 8.8.8.8 -g 192.168.1.1 -p 192.168.1.2-192.168.1.50 -d pds -i eth0

Obe aplikace je nutne spoustet v rezimu root