## 2021-05-24
    1. Improved graphs;
    2. Continued writing the report;

### Action points until next meeting:
    1. Write the thesis report, address comments.

## 2021-05-17
    1. Tried to measure some performance;
    2. Collected some graphs;

### Action points until next meeting:
    1. Performance evaluation:
      * Only consider the larger measurement sets (1000 runs)
      * Make tables with a simple statistical analysis of the numbers;
      * Use large datasets of images to test data transfers
      * Implement a FIFO queue of 5 images in the enclave for measuring the performance of writing from enclave to client (to eliminate caching effects)
    2. Security evaluation;
    3. Nicolae - read and comment on the thesis: https://www.overleaf.com/project/5ff61a40f9a6ba2d4b379c6c


## 2021-05-10
    1. Good progress, entire system works;
    2. Challenge: integrate TFLite inference C API with existing code and running the model inside the enclave, solved by creating an application in C that can be called inside the enclave.
    3. DL for submitting report: May 31st
    4. Investigate file transfer issues were solved; could not transfer through socket, had to allocate a buffer instead;

### Action points until next meeting:
    1. Performance evaluation - various aspects such as enclave setup speed, attestation, data streaming speed, etc;
    2. Security evaluation;
    3. Nicolae - read and comment on the thesis.

## 2021-04-30
    1. Had issues accessing the VM, issues now resolved;
    2. Client updated to NOT have to run inside an enclave;
    3. File transfer does not fully work - needs more investigation;
    4. running CURL from inside the enclave did not work;
    5. Thesis report written until implementation; need to modify implementation according to the latest changes; methodology to be updated with the evaluation approach/framework.

### Action points until next meeting:
    1. Investigate file transfer issues - try with smaller size first (< 16 M), to exclude size limits; next check the transfer logic;
    2. Data streaming;
    3. Performance testing.


## 2021-04-23
    1. Implement RA-TLS with Occlum and mbedTLS (using Occlum ra-mbedtls, dcap)
    2. can the verifier (client) be run outside of an enclave? most likely,
    and that will remove the requirement.

### Action points until next meeting:
    1. Integrate CURL to transfer model to the enclave;
    2. Run the verifier (client) outside of the enclave;
    3. Data streaming;
    4. Performance testing;



## 2021-04-16
    1. troubleshooting quote verification issue: 'warning a007' - due to
    vulnerability to LVI, no mitigations can prevent this atm; suggestion to
    "change platform" (however this is the Azure platform offered to businesses!)
    Statement from the Inclavare engineer;
    2. Continuing with occlum and mbedTLS (important to try and maintain Occlum
      as main working library OS)

### Action points until next meeting:
   1. Finish the set up the enclave+attest+establish secure channel chain;
   2. Guarantees about destroying enclave;
   3. Start thinking about measuring performance.



## 2021-04-09
    1. Tried out the Inclavare cluster attestation - implemented RA over the network, encountered an issue with certificate validation;
    2. In discussion with Inclavare about fixing the error;
    3. Next week: same scenario with Occlum.

### Action points until next meeting:
   1. Finish the set up the enclave+attest+establish secure channel chain;
   2. Guarantees about destroying enclave;
   3. Start thinking about performance.

## 2021-03-26
    1. Working on generating elements for secure channel establishment between client and enclave
    2. Full focus on DCAP
    3. Have a look at cluster attestation in Inclavare;

### Action points until next meeting:
   1. Configure support for DCAP;
   2. Finish the set up the enclave+attest+establish secure channel chain;
   3. Guarantees about destroying enclave;
   4. Start thinking about performance.


## 2021-03-19
    1. Trying to set up TLS between server and client;
    2. Configured remote attestation - quote confirmed;
    3. Discussion about how to correctly set up a TLS connection between the enclave and the model owner.
    4. Discussion about Occlum support for DCAP.

### Action points until next meeting:
    1. Configure support for DCAP;
    2. Finish the set up the enclave+attest+establish secure channel chain;
    3. Guarantees about destroying enclave;
    4. Start thinking about performance.


## 2021-03-12
  1. Good progress - performed remote attestation;
  2. Next steps: how to integrate remote attestation with TLS
  3. Next next step: speed to set up the enclave+attest+establish secure channel
  - how quickly can it be done?
  What about setup time of other library OSs?
  4. Other questions: destroying enclaves - how does that happen, is there a
  way to get any guarantee?
  5. Potential idea: for the scalability tests, set up a different - bigger virtual machine;
  6. Later: potentially compare results of "basic" operations (deployment, attestation, etc.)
  with Inclavare.

### Action points until next meeting:


## 2021-03-05
    1. Discussing the attestation architecture;
    2. Question - What is the attestation key;
    3. Discussion about potential project continuation.

### Action points until next meeting:
    1. Continue development as it is;




## 2021-02-26
    1. Focus on learning the tools - Occlum and SGX;
    2. Drew the architecture;
    3. Additional aspect to investigate: is there a way to terminate the enclave
    in a "lightweight" way (without e.g. terminating the VM).

### Action points until next meeting:
        1. Next steps: (a) figure out how to do attestation with ECDSA
        (data center attestation primitives)
        2. Next steps: (b) illustrate/describe the attestation process
        (we will discuss this next time)

## 2021-02-12
    1. Nicolae provided access to the Azure vm;
    2. Sri investigated several existing use cases;
    3. Discussion about the architecture;

### Action points until next meeting:
        1. SRI: Draw a (better) sketch of the architecture
        2. SRI: On the sketch start thinking how to evaluate the final system;


## 2021-02-05

    1. Updates to the research plan and research proposal: https://www.overleaf.com/4225284659vjxpwdjphhfn

### Action points until next meeting:
    1. SRI: Propose a design
    2. SRI: Try out running Inclavare and Occlum on AZURE
    3. NICOLAE: Provide access to an AZURE VM


## 2021-01-29
  1. Reading tips: Compare alternatives between Inclavare: https://inclavare-containers.io/
  2. Reading tips: https://www.ietf.org/archive/id/draft-ietf-teep-architecture-13.txt


### Action points until next meeting:
    1. Read through inclavare documentation and TEEP architecture
    2. Propose a design
    3. Try out running Inclavare and Occlum on AZURE
    4. SRI: Send public key to Nicolae  
    5. NICOLAE: Provide access to an AZURE VM



## 2021-01-15
  1. Discussion about the thesis progress;
  2. Mention Enarx.dev as an example of a project for application portability across different confidential computing platform architectures;

### Action points until next meeting:
  1. DONE NICOLAE: Fix the contract with RISE
  2. DONE NICOLAE: Review the literature list and maybe add more relevant papers and video presentations
  3. DONE SRI: Continue reading papers in the literature list;


## 2021-01-08

### Administrativia
    1. Sri submitted an application to RISE;
    2. Examiner: Gyorgi Dan, KTH supervisor Ezzeldin Shereen
    3. Suggestion to contact and keep in touch with the KTH supervisor;

### Thesis Discussion
    1. Create a reading list with paper about:
          * (HW isolation technology) Intel SGX, Intel TDX, AMD SEV;
          * (Library OS for SGX) Occlum, Graphene-SGX, SCONE;
          * **Inclavare** contianer management for enclave workloads;
          * Remote attestation in SGX - how it works, note the differences between initial version (2013) and the latest extensions called **"Data center primitives"**;
    2. Set up a template for the MSc report - suggestion to create an overleaf document;
    3. FYI Nicolae created an AZURE account to allow using VMs with SGX support;
    4. We agreed to meet every week until end of January to speed up the thesis.

### Action points until next meeting:
    1. SRI: Create and share a list of related literature
    2. (done) SRI: Set up a template for the MSc thesis on overleaf and share with Nicolae: https://www.overleaf.com/project/5ff61a40f9a6ba2d4b379c6c
    3. NICOLAE: Fix the contract with RISE
    4. (done) SRI: Share time plan for thesis;
