# STATIC Simulation System (SSS)

**Important Note: Currently this repository only contains a simple request/response example. Additional API functions will be added as soon as they are ready.**

The XTRABYTES DICOM API is your gateway to the XTRABYTES core. Using an API, you will easily be able to integrate your custom application with XTRABYTES. Since the XTRABYTES core code is not yet open-source, the STATIC Simulation System will allow you to begin integrating with XTRABYTES without waiting for the core source code. When the XTRABYTES core is released, switching your application to the mainnet will be a simple matter of changing the API endpoint.

**Overview of DICOM, SSS and the XTRABYTES Testnet**
![sss testnet overview](https://user-images.githubusercontent.com/17502298/39838169-8879c0b8-53a6-11e8-8f1a-857b29cef76c.png)

**(Future implementation) Overview of DICOM, the STATIC network and the XTRABYTES Mainnet**
![sss mainnet overview](https://user-images.githubusercontent.com/17502298/39838220-b8737d0e-53a6-11e8-9483-33838869dd78.png)

## Getting Started

#### Building SSS on Debian / Ubuntu
Install prerequisites.

```
sudo apt install git build-essential libboost-all-dev libssl-dev curl
```

Clone this repository.

```
git clone https://github.com/borzalom/sss.git
```

Switch directories and build the binary.

```
cd sss
mkdir build
make -f makefile.linux
```

Run the compiled binary.

```
./sss-daemon
```

#### Testing SSS

The daemon is now running on port 8080 and any requests to the daemon will be logged in that terminal window. Open a second terminal window and use the following command to post a "echo" request to the daemon:

```
curl --insecure -d '{"dicom": "1.0", "type": "request", "method":"echo", "params": "xcite" }' -H "Content-Type: application/json" -X POST https://127.0.0.1:8080/v1.0/dicom
```

You should receive the following reply from the daemon:

```
{
  "dicom": "1.0",
  "type": "reply",
  "echo": "xcite"
}
```
