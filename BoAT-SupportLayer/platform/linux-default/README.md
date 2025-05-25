# Configuration on linux-default


## 1. Introduction

This article introduces how to use BoAT Infra Arch's development template `BoAT-ProjectTemplate` on `linux-default` platform to build demo programs for different blockchains.

### Compilation Environment
Operating System:
```
ubuntu 16.04
```
Software Dependencies:
```
gcc
   sudo apt install gcc -y
make
   sudo apt install make -y
git
   sudo apt install git -y
python3
   sudo apt install python3 -y
curl
   sudo apt install curl -y
```
Note: You can develop either on a linux computer or in a virtual machine running linux on Windows.

## 2. Building Directories

Assuming `<Linux Root>` to be the root directory for `linux-default` compilation:

1. Download BoAT-ProjectTemplate

Open a terminal and move to `<linux Root>`. Use `git clone` to download`BoAT-ProjectTemplate` in `<Linux Root>`:
```
git clone git@github.com:boat-x/BoAT-ProjectTemplate.git
```
or
```
git clone https://github.com/boat-x/BoAT-ProjectTemplate.git
```

2. Move to `<Linux Root>/BoAT-ProjectTemplate/`  and modify `BoATLibs.conf`:

Replace `BoATLibs.conf` with below content:
```
BoAT-SupportLayer
BoAT-Engine
```


3. Execute the configuration script in `<Linux Root>/BoAT-ProjectTemplate/`

```
python3 config.py
```
Select choice according to the prompt:
```  
We will clone the BoAT-SupportLayer repository, which may take several minutes

Input the branch name or null:
```
Type `main`and enter to select the main branch of `BoAT-SupporLayer`:
``` 
Input the branch name or null:main
branch name is [ -b main]

git clone -b main git@github.com:boat-x/BoAT-SupportLayer.git

Cloning into 'BoAT-SupportLayer'...
remote: Enumerating objects: 2930, done.
remote: Counting objects: 100% (704/704), done.
remote: Compressing objects: 100% (327/327), done.
remote: Total 2930 (delta 441), reused 589 (delta 362), pack-reused 2226
Receiving objects: 100% (2930/2930), 3.40 MiB | 21.00 KiB/s, done.
Resolving deltas: 100% (1826/1826), done.
git cmd succ


We will clone the BoAT-Engine repository, which may take several minutes

Input the branch name or null:
```
Type `main` and enter to select the main branch of `BoAT-Engine`:
```
Input the branch name or null:main
branch name is [ -b main]

git clone -b main git@github.com:boat-x/BoAT-Engine.git

Cloning into 'BoAT-Engine'...
remote: Enumerating objects: 900, done.
remote: Counting objects: 100% (39/39), done.
remote: Compressing objects: 100% (27/27), done.
remote: Total 900 (delta 18), reused 22 (delta 12), pack-reused 861
Receiving objects: 100% (900/900), 527.23 KiB | 37.00 KiB/s, done.
Resolving deltas: 100% (567/567), done.
git cmd succ


overwrite the Makefile?(Y/n):
```
Type `y` to generate the Makefile:
```
Yes

 Select blockchain list as below:
 [1] ETHEREUM          : 
 [2] PLATON            : 
 [a] QUORUM            : 
 [0] All block chains
 Example:
  Select blockchain list as below:
  input:1a
  Blockchain selected:
   [1] ETHEREUM
   [a] QUORUM

input:
```
Choose one or more supported blockchains. For example, choose 1 to select Ethereum:

```
input:1
Blockchain selected:
 [1] ETHEREUM

Select the platform list as below:
[1] linux-default             : Default linux platform
[2] Fibocom-L610              : Fibocom's LTE Cat.1 module
[3] create a new platform
```
Type `1` to select `linux-default`:
```
1
 
platform is : linux-default

include BoAT-SupportLayer.conf

include BoAT-Engine.conf


./BoAT-SupportLayer/demo/ False
./BoAT-Engine/demo/ True
Configuration completed
```
After a successful configuration, the directories will look like:

```
<Linux Root>
|
`-- BoAT-ProjectTemplate
      |-- BoAT-SupportLayer
      |-- BoAT-Engine
      |-- BoATLibs.conf
      |-- config.py
      |-- Makfile
      |-- README.md
```



## 3. Building

There are two building choices: build static libraries only or build demo executable.

### 1. Build static libraries

```
make clean
make all
```
After successful compilation, 2 static libraries `libboatvendor.a` and `libboatengine.a` will be generated in `<Linux Root>/lib`. These libraries are required by demo executable.

### 2. Build BoAT demo for Ethereum
```
make demo ETHEREUM_DEMO_IP="x.x.x.x" 
```
Where `"x.x.x.x"` is the IP address of the node RPC。

After successful compilation, a demo executable will be generated in `<Linux Root>/build/BoAT-Engine/demo`：
```
demo_ethereum
```

Run the executable to demonstrate smart contract invocation.


### 3. Troubleshooting
#### Issue 1:
```
curlport.c:33:23: fatal error: curl/curl.h: No such file or directory
```
Please install `libcurl4-gnutls-dev`:
```
sudo apt install libcurl4-gnutls-dev
```
#### Issue 2:
```
boatssl.c:26:25: fatal error: openssl/evp.h: No such file or directory
```
Please install `libssl-dev`:
```
sudo apt install libssl-dev
```

