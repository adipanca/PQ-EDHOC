# Tests PQ-EDHOC

This folder contains tests for PQ-EDHOC. The tests can be executed on an embedded board, e.g., nrf51dk. The tests use Zephyr OS for building. 

## Configuration
### Cryptographic engines
```bash
CRYPTO_ENGINE += -DPQM4
CRYPTO_ENGINE += -DTINYCRYPT
CRYPTO_ENGINE += -DCOMPACT25519
```

### Select PQC algorithms for KEMs and PQC digital signature
```bash
# Select the PQ KEM algorithm to be used, 
FEATURES += -DKYBER_LEVEL_1
#FEATURES += -DKYBER_LEVEL_3
#FEATURES += -DHQC_LEVEL_1 
#FEATURES += -DBIKE_LEVEL_1

# Select the PQ Signature algorithm to be used
FEATURES += -DFALCON_LEVEL_1

#FEATURES += -DDILITHIUM_LEVEL_2
#FEATURES += -DHAWK_LEVEL_1
#FEATURES += -DHAETAE_LEVEL_2
```

## Compile and run:
```bash
cd test_pq/
source ~/zephyrproject/.venv/bin/activate 
rm -rf build/
west build -b nrf52840dk_nrf52840 -- -DUSE_TEST_EDHOC=1 -DUSE_X5T=1 -DUSE_SUIT_7=ON -DUSE_INTE_NUM=100 -DMEASURE_CLK=1 
west flash
```

### FLags
#### Select the PQ EDHOC TEST
```bash
-DUSE_TEST_EDHOC=1
```
#### Select X5T or X5chain credential type with one of this two flags
```bash
-DUSE_X5T=1 
-DUSE_X5CHAIN=1 
```
#### Number of times to run the protocol
```
-DUSE_INTE_NUM=100
```
#### For Benchmark measuring accurate speed
```
-DMEASURE_CLK=1
```

#### Fpr measure speed toegther with powerconsumption without overcost
-DMEASURE_LATENCY_PER_THREAD=1

#### For Benchmark measured power consumption
-DPOWER_MEASUREMENTS=1

#### Select the cipher suit under test and the corresponding features in the makefile_config.mk

- Cipher suit 2 ```-DUSE_SUIT_2=ON``` with
```
FEATURES += -DDH
```

- Cipher suit 7 ```-DUSE_SUIT_7=ON``` with 
```
FEATURES += -DKYBER_LEVEL_1
FEATURES += -DFALCON_LEVEL_1
```

- Cipher suit 9 ```-DUSE_SUIT_9=ON``` with
```
FEATURES += -DKYBER_LEVEL_3
FEATURES += -DFALCON_LEVEL_1
```

- Cipher suit 10 ```-DUSE_SUIT_10=ON``` with
```
FEATURES += -DHQC_LEVEL_1
FEATURES += -DFALCON_LEVEL_1
```

- Cipher suit 11 ```-DUSE_SUIT_11=ON``` with
```
FEATURES += -DBIKE_LEVEL_1
FEATURES += -DFALCON_LEVEL_1
```

- Cipher suit 12 ```-DUSE_SUIT_12=ON``` with
```
FEATURES += -DKYBER_LEVEL_1
FEATURES += -DDILITHIUM_LEVEL_2
```

- Cipher suit 14 ```-DUSE_SUIT_14=ON``` with
```
FEATURES += -DKYBER_LEVEL_1
FEATURES += -DHAWK_LEVEL_1
```

- Cipher suit 15 ```-DUSE_SUIT_15=ON``` with
```
FEATURES += -DKYBER_LEVEL_1
FEATURES += -DHAETAE_LEVEL_2
```

- Cipher suit 17 ```-DUSE_SUIT_17=ON``` with
```
FEATURES += -DKYBER_LEVEL_1
```