rm -rf build/
west build -b nrf52840dk_nrf52840 -- -DUSE_X5T=1 -DUSE_SUIT_7=ON 
west flash