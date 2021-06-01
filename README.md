# Master Thesis - Confidential Computing in Public Clouds

This repository consists of all resources that are used to build a master thesis topic as written above. Three main folders below are source code used for implementation:
1. ServiceProvider = server repository who owns SGX capable machine
2. MLClient = client repository who owns a machine learning model
3. DataClient = client repository who owns data for the machine learning model

# Getting Started

If you have not installed SGX driver in your platform, please follow either one of these links below:
1. https://download.01.org/intel-sgx/sgx-linux/2.11/docs/Intel_SGX_Installation_Guide_Linux_2.11_Open_Source.pdf
2. https://github.com/intel/linux-sgx-driver

When you manage to configure the SGX, you can start downloading Occlum and follow its manual installation from the folllowing link:
https://github.com/occlum/occlum

Configure SGX Data Center Attestation Primitives (DCAP) components, follow the instruction provided by the link below:
https://software.intel.com/content/www/us/en/develop/articles/intel-software-guard-extensions-data-center-attestation-primitives-quick-install-guide.html

Synchronize the guideline in that link with the original DCAP project in the following link:
https://github.com/intel/SGXDataCenterAttestationPrimitives

Make sure both sample codes, the Quote Generation and the Quote Verification work successfully. 

# Build Program

To build the program, those instances (ServiceProvider, MLClient, and DataClient) should be installed in different Docker containers. Therefore, it will be better to install Occlum software by using Docker container. It is also important to create a new network interface to support communication between two or more docker containers. Follow the following website to configure the interface:
https://medium.com/techanic/docker-containers-ipc-using-sockets-part-2-834e8ea00768

1. Install ServiceProvider in one Occlum container including the port interface for networking:
`docker run --network=interface_name --name server --expose port_number -it --device /dev/sgx occlum/occlum:version-ubuntu_version`


