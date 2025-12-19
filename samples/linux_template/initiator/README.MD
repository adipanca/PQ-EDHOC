

The repository includes submodules. Clone it using the `--recurse-submodules` option:
## Dependencies 
[liboqs](https://github.com/open-quantum-safe/liboqs) - An open source C library for quantum-safe cryptographic algorithms. This library need to be compile without openssl. Following the steps below:
```
 mkdir build
 cd build
 cmake -G Ninja .. -DOQS_USE_OPENSSL=OFF
 Ninja 
```

## Configuring
To configure the examples at this project and correctly use the **PQ-uEDHOC** library, you must edit the configuration file [makefile_config.mk](makefile_config.mk). 
For now just use the same makefile_config.mk configuration for both client and responder that i provide you here to test the library with classical DH.

## Build and Run
```
make clean
make -j
./build/responder
```
