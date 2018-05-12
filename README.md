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
sudo apt install git build-essential libboost-all-dev libssl-dev curl libleveldb-dev
```

Install rapidjson (we'll get better instructions)

Add `deb http://ftp.debian.org/debian/ unstable main contrib` to `/etc/apt/sources.list`, then

```
sudo apt-get update
apt-get -t unstable install rapidjson-dev
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

The daemon is now running on port 8080 and any requests to the daemon will be logged in that terminal window. Open a second terminal window and use the following command to test a connection to the daemon:

```
curl --insecure -d '{"dicom":"1.0","payload":"{\"method\":\"connect\",\"pubkey\":\"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7dab0whrLtz8yF6ZgBh0\\nQz2ph07000V3hw+XSqR7rHB\\\/07Wwe5v35TRqw2M0xKDDRAl5FYtao+0eKUeoAkP1\\nbFml7lSCWuX9zoBjB72SYhucrbFQF9MYNGjataLhhfFW7XNtUPszL4T5j64J6K1p\\n8JCbdb8KBYOnE17jTYV0uLHFFq8ONm48JBH3Z3CE\\\/AA+dwHRXGbbmqeK5iuOckEg\\nmdET6HEKsDn6ekpFPHvvMLHz6+WMQAGRcoWfBgTTtUJsV8ggt\\\/8PVK+QToIPrt6O\\n5tRFdkwlhGYOjl5eylfq2i\\\/eGY1g+lPi9P9iVeHpncd7mrWcPKMjUY1ye9x\\\/+xsn\\nqQIDAQAB\\n-----END PUBLIC KEY-----\\n\"}","signature":"ojxXAZzAQAVn9Ccqkvh0hWmTtmoSAh40\/c+sYtdivuwQpcbYLm7BrHeYDvxFFfcL\nbgjcktJCTz0SRzpHmNlc2okw4wMilMOu6f8K0o6+1J3xgbhoRA8zPgspUn+wItV2\nDr05bVEQP8UDlUODGRnJ6eBYpZzAQ3\/PzZk7zhTZPf7qVBW3d5OVUna5rYmCEA95\nRHIaMtQBzvQUGgwLUFXrUuB6HIUXqUrVXwbjeG5mrZL4Cos6RPJDBckTA0Uz8bvX\n8V3VvgIdkejWEYzScZkMGOaPU+ApBb9qMJE4PX+hkYWbLAAZ8xdLkz7y\/mkWdjni\n4EGCxnMsxMxZZ0n0GdH5XA==","pubkey":"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7dab0whrLtz8yF6ZgBh0\nQz2ph07000V3hw+XSqR7rHB\/07Wwe5v35TRqw2M0xKDDRAl5FYtao+0eKUeoAkP1\nbFml7lSCWuX9zoBjB72SYhucrbFQF9MYNGjataLhhfFW7XNtUPszL4T5j64J6K1p\n8JCbdb8KBYOnE17jTYV0uLHFFq8ONm48JBH3Z3CE\/AA+dwHRXGbbmqeK5iuOckEg\nmdET6HEKsDn6ekpFPHvvMLHz6+WMQAGRcoWfBgTTtUJsV8ggt\/8PVK+QToIPrt6O\n5tRFdkwlhGYOjl5eylfq2i\/eGY1g+lPi9P9iVeHpncd7mrWcPKMjUY1ye9x\/+xsn\nqQIDAQAB\n-----END PUBLIC KEY-----\n"}' -X POST https://127.0.0.1:8080/v1.0/dicom
```

You should receive a similar reply from the daemon:

```
{
    "dicom": "1.0",
    "method": "connect",
    "payload": "{\"session_id\":\"d963c05c-4560-4e94-b92d-d08dc97a0b61\",\"pubkey\":\"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp8GuaSaEZaCBf3fd4W3\\\/\\nSKdSK6TeAwDeOc6HjgcaOEuxHtWvfq+eOUo5cLgX3od1CNAyxLs+\\\/EHwJGL1Tchj\\nK0rOMto+ITjxQp2OM2GQi05lPq5wNY4WCThr5SGqxIdHAeU8iFCcc5ZOFvpiSE6T\\ntHOs4f9gKxwDYwrcK\\\/6uEdn8NDNpDRHfNYGHYqvAnujyagy0M70OLE93fMKkF2mr\\n2zDlFZt+hUxtauJIiRBTuxNBlVtGRboUN+NDEjQt7y5RCrB+yzirSTcOonYaG+K\\\/\\nztBwECh6KYaQjfkbLSNbMil8b9SQb\\\/ch5B6Z6AH6mwIs9ePE4GPJUZqHXJQZOpi8\\n0QIDAQAB\\n-----END PUBLIC KEY-----\\n\"}",
    "signature": "Lgg+QJQiqnYhppi3rl0Rw7ctiwxcE6du1z3lVxd555iK+sgYhYyMed97H1wsz89I\nhx4sai71UlnuoyRTTQpNOIYWL8BgXOFREBXFCcRTrygMyvfI7Wcw63Xpy5V\/FZ+7\nKdXHE\/QhIsyl2KOCObGGzoUQJYD9UuXIXkrYqbJ3BMFzK\/JDyVtkp3WxkCzcfNPi\nYNpX+1pBCLld5j2CkHU9RzujX64Q8AFQcE\/DgtxOJjhWXJnqX7AxbtsBQ6YKWPiL\nmfAa+NB4uB2ghPkfZIVuancwdKXoI5wMSDN0en4BwH68OHsSn1SrhLNVJBC7f6Bx\nMPtzKuY+C\/J+1OlvamoiHg==\n"
}
```

Client libraries and a CLI tool are upcoming to aid testing.

#### Protocol/API

The API should be considered pre-alpha and almost certainly will change significantly in the near future. Expect things to break.

Refer to the client libraries for insight into the capabilities of the API, documentation will be released once the API has stabilised.

#### Contributing

Code-style is TBD, but for now:

- Tabs not spaces
- Tabsize of 4
- Unix line endings

