# *GuardBox*

This is a demo of *GuardBox*.  The code in the repository uses libpcap instead of DPDK to capture packets from the NIC and has been streamlined to run on almost any computer with an Intel processors (e.g. a laptop with an Intel i5/7/9 ... ) to quickly demonstrate the basic idea of *Guardbox*.

This demo captures TCP-based packets on a NIC, encrypts the payload of a packet in the Enclave with AES and passes it out of the Enclave. Then, decryption is performed outside the Enclave and the restored packet is sent to another NIC.

## Build and Run

Here is an example of Ubuntu as an operating system.

### Prerequisites

- libpcap-dev

```
sudo apt install libpcap-dev
```

- openssl

see https://github.com/openssl/openssl

- Intel SGX SDK

see https://github.com/intel/linux-sgx

### Compile and Run the Code

The code is compiled and run in SGX Simulation mode by default: 

```
make
./app
```

Since most computers have only one NIC (assumed to be named eth0) for external communication , the code captures the packets on that NIC and forwards the encrypted-decrypted packets to loopback (lo). A straightforward example after running the program is visiting an HTTP website. For example, when visiting http://portquiz.net/ in a browser, the same HTTP packets on loopback as that on eth0 can be captured.