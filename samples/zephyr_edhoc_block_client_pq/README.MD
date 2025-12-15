# EDHOC Constrained Device Samples

## General
This folder contains a samples intended to be executed on a constrained device running over constrained 6LowPAN network (IPv6 over BLE)

* initiator - PQ-EDHOC initiator running on top of a CoAP client with Block-Wise Transfer

Tested on 

* initiator - tested on nRF52840 with IPv6 over BLE
* responder - tested on Ubuntu 22.04.4 LTS with IPv6 over BLE

## Requirements
* Zephyr OS 3.4.0 is needed for building these samples.
* A BLE board is needed for testing (Tested with nrf52840dk_nrf52840)
* A Linux computer with BLE (Tested on Ubuntu 22.04.4 LTS)

## Setup: nRF52840 PQ-EDHOC initiator - Linux host PQ-EDHOC responder

### open port 5683
make sure that the CoAP port 5683 is open on the Linux host. The port can be opened with UFW (Uncomplicated Firewall).
```bash
sudo ufw allow 5683/udp
sudo ufw enable
sudo ufw status
# which prints:

# Status: active

# To                         Action      From
# --                         ------      ----
# 5683/udp                   ALLOW       Anywhere                  
# 5683/udp (v6)              ALLOW       Anywhere (v6)    
```
### Setting IPSP in the Linux station
PSP (Internet Protocol Support Profile) Node role. IPSP is the Bluetooth profile that underneath utilizes 6LoWPAN, i.e. gives you IPv6 connectivity over BLE. You can find more info about this example base at `https://docs.zephyrproject.org/2.7.6/samples/bluetooth/ipsp/README.html`
* Make sure the Linux kernel has been built with Bluetooth 6LoWPAN module (CONFIG_BT_6LOWPAN=y):
- For check you can use the following comand, if yes or m is enable. If m then you should also check if:
```
grep CONFIG_BT_6LOWPAN /boot/config-$(uname -r)
```
```
modinfo bluetooth_6lowpan
```
If is not enable you shoul rebuild your kernel with the fucntionality enabled
- proceed to enable it in Linux before open the bluethoot board with the following commands (as root)
```
sudo modprobe bluetooth_6lowpan
echo 1 | sudo tee /sys/kernel/debug/bluetooth/6lowpan_enable 
```
- may you also need to select
```
echo "6" > sudo /sys/kernel/debug/bluetooth/hci0/conn_min_interval 
echo "7" > sudo /sys/kernel/debug/bluetooth/hci0/conn_max_interval 
```

### Configure and run the linux base PQ-EDHOC responder
* The Linux host example is in the folder `samples/linux_edhoc_block_pq/responder` 
- Configure the PQC KEM and PQC digital signature you want to run in `makefile_config.mk` and the appropiate criptography engines following the process on the corresponding README.
- Set to use IPV6 address by defin the follows at the start of `samples/linux_edhoc_block_pq/responder/src/main.cpp` file:
```
#define USE_IPV6
```
- Build and run the responder:
```
make clean
make
./build/responder
``` 
### Configure and run the zephyr OS base PQ-EDHOC initiator
* The zephyr OS example example is inside this folder `samples/zephyr_edhoc_block_client_pq/initiator_test_benchmark` 
* Configuration
Cryptographic engines
```bash
CRYPTO_ENGINE += -DPQM4
CRYPTO_ENGINE += -DTINYCRYPT
CRYPTO_ENGINE += -DCOMPACT25519
```
Select PQC algorithms for KEMs and PQC digital signature
```bash
# Select the PQ KEM algorithm to be used, 
FEATURES += -DKYBER_LEVEL_1

# Select the PQ Signature algorithm to be used
FEATURES += -DFALCON_LEVEL_1
#FEATURES += -DDILITHIUM_LEVEL_2
#FEATURES += -DHAWK_LEVEL_1
#FEATURES += -DHAETAE_LEVEL_2
```
* connect the BLE board to the computer used for building the samples over USB.
* build and flash the sample:
```bash
west build -b nrf52840dk_nrf52840 -- -DUSE_X5T=1 -DUSE_SUIT_7=ON 
west flash
```
FLAGS
- Select X5T credential type with this flag
```bash
-DUSE_X5T=1 
```
- Select the cipher suit under test and the corresponding features in the makefile_config.mk
Cipher suit 2 ```-DUSE_SUIT_2=ON``` with
```
FEATURES += -DDH
```
Cipher suit 7 ```-DUSE_SUIT_7=ON``` with 
```
FEATURES += -DKYBER_LEVEL_1
FEATURES += -DFALCON_LEVEL_1
```
Cipher suit 12 ```-DUSE_SUIT_12=ON``` with
```
FEATURES += -DKYBER_LEVEL_1
FEATURES += -DDILITHIUM_LEVEL_2
```
Cipher suit 14 ```-DUSE_SUIT_14=ON``` with
```
FEATURES += -DKYBER_LEVEL_1
FEATURES += -DHAWK_LEVEL_1
```
Cipher suit 15 ```-DUSE_SUIT_15=ON``` with
```
FEATURES += -DKYBER_LEVEL_1
FEATURES += -DHAETAE_LEVEL_2
```

* Optionally the board can be connected to a serial terminal for observing status messages.

* Find the Bluethot address or your board by ussing
```
nrfjprog --memrd 0x100000A4 --n 8
```
For example for my board return:
```
0x100000A4: 384B8285 2294EFB7  
```
which correspond with address `B7:EF:38:4B:82:85`
* NOTES:
    - Be sure that the device is not connected from before trough bluethoot manager
    - Wait to the IPS sample run before connect
* Connect to the board
echo "connect EF:B7:38:4B:82:85 2" | sudo tee /sys/kernel/debug/bluetooth/6lowpan_control > /dev/null  
* assign static IP:
ip address add 2001:db8::2/64 dev bt0 
