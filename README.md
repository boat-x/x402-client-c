# x402-client-c

This is a C-language demo showing on-chain machine payment based on [x402 protocol](https://www.x402.org/). This repository is the client side.

The client-side x402 protocol is implemented in the C language based on [BoAT machine wallet SDK](https://github.com/boat-x/BoAT-ProjectTemplate). Machine requests for resource from the x402 server and receiveds a 402 status code with payment request

The demo can be compiled and run in desktop linux (or Cygwin on Windows), or be cross-compiled to run on a Fibocom L718 development board. It can also ported to other hardware based on BoAT's hardware platform abstraction.


## How to Build

1. Fibocom L718 development boards and SDK are required. The development environment should be linux.
Contact Fibocom for the resources.

If you don't have a Fibocom L718 board and want to test it on computer, please follow below guides.

2. Clone x402 from [Coinbase's github repository](https://github.com/coinbase) and follow [Coinbase Developer Platform Docs](https://docs.cdp.coinbase.com/x402/docs/quickstart-sellers) to deploy a x402 server for testing.
    `git clone https://github.com/coinbase/x402.git`

Note: Fibocom L718 is a 4G cellular module and cannot access servers in local area network. To run `x402-client-c` on Fibocom L718, the x402 server must be deployed on Internet.

To test `x402-client-c` on computer, you can deploy x402 server on local computer.

3. Clone this project:

    `git clone https://github.com/boat-x/x402-client-c.git` 

If you don't have a Fibocom L718 board and want to test it on computer, please modify the `TEST_ON_COMPUTER` flag to `no` in the project root `Makefile` and omit the below Step 4 ~ 5:
    `TEST_ON_COMPUTER = no`

Modify `g_x402_server_url` in x402-client-c/x402-demo.c according to x402 server deployment configuration in Step 2:
    const BCHAR *g_x402_server_url = "http://127.0.0.1:4021/weather";

4. Copy the entire cloned project to L718 develpment SDK's user app directory:

    `cp -r x402-client-c build_env_mini/app/app`

5. Modify **build_env_mini\app\app\Makefile** to configure the toolchain:
```
include ../../global_opt.mak
export GCC_PATH = $(shell pwd)/../../build/usr/bin
export MIN_CC 			= $(GCC_PATH)/arm-linux-gcc
export MIN_LD 			= $(GCC_PATH)/arm-linux-gcc
export MIN_AS       	= $(GCC_PATH)/arm-linux-as $(CPUFLAGS)
export MIN_CXX       	= $(GCC_PATH)/arm-linux-g++ $(CPUFLAGS)
export MIN_AR        	= $(GCC_PATH)/arm-linux-ar
export MIN_OBJCOPY   	= $(GCC_PATH)/arm-linux-objcopy
export MIN_RANLIB    	= $(GCC_PATH)/arm-linux-ranlib
export MIN_STRIPTOOL 	= $(GCC_PATH)/arm-linux-strip
export MIN_STRIP     	= $(GCC_PATH)

INCLUDE += -I../fiboframework/framework/c/inc
INCLUDE += -I../fiboframework/interfaces/atServices
INCLUDE += -I../fiboframework/interfaces/audio
INCLUDE += -I../fiboframework/interfaces/modemServices

LDLIBS +=



.PHONY: all
all: 
	make -C ./x402-client-c all


clean:
	make -C ./x402-client-c clean
```

6. Configure credentials

Copy `credentials.key.example` to `credentials.key` and replace `g_payer_key` value with actual payer's private key. The private key should be a "0x"-prefixed HEX string representing the plain text 256-bit private key (e.g., "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").


7. Build

If you are cross-compiling `x402-client-c` for Fibocom L718:
    Change directory to **build_env_mini/app/app**:

    `cd build_env_mini/app/app`

If you are testing `x402-client-c` on computer:
    Change directory to **x402-client-c**:

    `cd build_env_mini/app/app`

Build the demo:

```
make all
```

The built executables will be placed at:
`x402-client-c/build/x402-demo-app`

To clean:
`make clean`
