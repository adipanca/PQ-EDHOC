rm -rf build/
west build -b nrf52840dk_nrf52840 -- -DUSE_X5T=1 -DUSE_SUIT_14=ON -DUSE_CLEAN_IMP
west flash