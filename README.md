# How to build
## Linux Build
User can run build on ubuntu machine using command:

`./build_ubuntu.sh`

Prerequisites: user in a 'sudo' group.
To update version of project dependencies, change version numbers at the top of build_ubuntu.sh
Otherwise, default versions will be used.
Produced binaries can be found in ./out folder.

## Windows Build
### Prerequisites
1. Install Visual Studio 2017 or above
2. Install Java OpenJDK 17
3. Ensure "JAVA_HOME" environment variable is set to <OpenJDK_installation_path>

### 
User can run build on Windows machine using command:

`build-dependencies.bat <Visual Studio Build Directory> <Optional: BKPS/Verifier Output Build Version>`

e.g. build-dependencies.bat C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build 1.0.1  
\<Visual Studio Build Directory\>: Visual Studio build directory with both vcvarsall.bat and vcvarsamd64_x86.bat scripts , these are required for initializing environment for building the dependencies on Windows platform.

\<Optional: BKPS/Verifier Output Build Version\>: Version of built BKPS/Verifier Java binaries, default: 1.0.0. This setting will be reflected at the naming of BKPS/Verifier Java binaries built from the script, e.g. bkps-1.0.0.jar workload-1.0.0.jar

To update version of project dependencies, change version numbers in config.txt.
Otherwise, default versions will be used.
Refer to below table for more details on currently supported dependencies for build-dependencies.bat.

| Name           | Supported Value | Download Source |
|:------------------|:----------------|:------------------------------------------------------------------------------------------------------------------------------|
| always_build              | 1               |
| openssl.version              | 3.5.5           | https://github.com/openssl/openssl.git
| libspdm.version              | 3.8.2           | https://github.com/DMTF/libspdm.git
| libcurl.version              | 8.12.1          | https://curl.se
| boost.version              | 1.84.0          | https://github.com/boostorg/boost/releases
| gtest.version              | 1.14.0          | https://github.com/google/googletest.git

Produced binaries can be found in ./out_windows folder.

## Manual build

To build each component manually, refer to README files:
- [BKPS](./bkps/README.md)
- [SPDM Wrapper](./spdm_wrapper/README.md)
- [Verifier](./Verifier/README.md)
- [FCS Server](./FCS/README.md)
- [BKPProgrammer](./bkpprogrammer/README.md)
- [BKPS UI](./bkps_ui/README.md)

## BKPS UI demonstration tool

`bkps_ui` is a BKPS automation tool with GUI and CLI modes. It helps users visualize how to set up BKPS correctly, from installation through BKP server setup, AES artifacts, BKP server configuration, and device provisioning. It includes the following pipelines, run in order:

- **Installation** — install dependencies, set up the BKPS repository, security provider, SSL certificates, keystore, and BKPS configuration.
- **Server** — initialize the database, start the BKPS server, create the super admin, authentication keys, and BKPS keys.
- **AES** — generate QEK and ccert files.
- **Configuration** — create a BKPS configuration, programmer user, and `bkp_options.txt`.
- **Programming** — generate JIC, program JIC, BKP prefetch, PUF activate, set authority, and provision.

**Disclaimer:** This tool is for demonstration purposes only.

### Linux

```bash
cd bkps_ui
./setup.sh && ./run.sh
```

### Windows

```bat
cd bkps_ui
.\setup.bat && .\run.bat
```

`setup` creates a local Python virtual environment and installs required packages. `run` launches the GUI. Optional CLI usage and configuration details are in [bkps_ui/README.md](./bkps_ui/README.md).

## Release notes

| Version | Date      | Release note                                                                                                                                                                                                                                                                             |
|:--------|:----------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 24.3.1  | 12/2/2024 | BKPS + bkpprogrammer + BKP App opensourced                                                                                                                                                                                             
