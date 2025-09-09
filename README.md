# NATWORK T5.2

The goal of this project is to implement a distributed network intrusion detection system using random forests.
The classification is done in the data plane of programmable switches, utilizing resources that would otherwise be
wasted. These free resources are scarce, therefore distinct parts of the ML model are uploaded to different switches.
Switches belong to different administrative domains, so the model must be distributed in a secure manner.
For this reason federated learning is used: each domain trains/refines its own model and the results are combined
by a centralized coordinator, which then distributes the updated model to the various domains.
The switches within each domain work together to classify packets: they use different slices of the same ML model.
Different network slices execute the inference separately; they only work together to build a better model.

The project is currently Work In Progress.
Its federated learning capabilities are not yet implemented, the coordinator component is currently no-op.

<details open>
<summary>Current plan overview (diagram)</summary>

![](https://www.plantuml.com/plantuml/svg/fLHVQzn647_VJp4ebBEXvzI2lXWJOWTA2ctwO4DRUiMCLYDfyMfNp8vwkPRaitSadK_MEQuBUPDsvlTdvy--JO8iVUjDkdUXGyOMIggmzt9B7-NAkpgq50Gi1I4sbqbsdjwOodc2Vmp0-yZkxnW4_PphgHBpoLo-tYSR9YiOQeLa7qYsaU_XnZjBS9KfIOYb1juf2KVlYOTJJ60F1tTeIXGiC6dU7hW9iOARhHFRmAlp4P36lpiyDu-XSBbUpo6uWEoxi--_0KLNFcuJO2WtmOMAc88I3qBP2tBvGYv_NYx_dt9BXlNw3ImEbEJ7jkFu5q4RI_9AK05QspFQ7PGSkpHm-DYNaFsYXtvqVD8dAg6AFA5069rArvkW9Wvu3GOdaJLmEjuhZWHtU6IgxzJM59iidG-tseJnMjbn3JHxaNmrgWbD-U2n8A-eJ_yn6zTVd8thuzaedZJh-ldPA1QpKGobdaE3pvz_UYXn6hYo5yZp1Nd-F7d-9VBZdbr_RS-AfO7BHTEAeTghTx4TTbH5OYyNPlMe_EzZ4lXjv6lqy-xZq-ZlStHdLbCMV6PND_BvqVwj3fzFWlaSp8-3Kmjk6QlAMJZfqDwJfDDC8OU4OqW-1sU-lS73z4GkNK29F0tF_6yUVO-RUxntQiO5Ak6XTTF-LaoqTm1CAVPiAMLFoUR_WUi7AebHbCqJyj1LK8f6fu6qhTDR05ZNJ3MAY-5Y4rhYcWxYQLAtJCe2WRRJyKBu-FKenktRavAYuK2NcUaP3r7e75uLVNA1Ke8_p6r3KBbwC9MQsFiI2W8cBA7Ys8xlEqY4iTfdnjpiab0Bc5BVTeFpT67MC0rr0cHIk0WneC2u_jPhhjCcZ_S4QJ3ioqd909pGMNsc68jz8l38DJqKe8nXfIHEm0M91z2fcX2cK4kJ85RAw5IuwpYYRGOp7o84scyMZfLE9815x0L8Sm15TDn0TXrf-gyqRHweExJIet_DP2d82FrM-Ob9kSW0R6cy8bDotWqfM2iooT05Ivr2s5LY_ZHlAPHzw_y5)

</details>

<details>
<summary>Current plan: sequence diagram</summary>

![](https://www.plantuml.com/plantuml/svg/TLJDJjj04BxlKuo2Aee4j9LwYX22Kg4YbPO2bQegbs4zDgkiPzETSS8X3z_rJwoDIq_PjMU-dsyclX35g4tjZImThp1Y3K9_6c9BjoI25LrwLp5OOgMOLHLKOkFraLwqgwY9TLTbRF2UhBh00hClGLHcW0BFxSaSFeKNc7qZtOIuX4ju6ng5K4ATuDpAqz7CT1Nt9A69bgHzYI0higvq5dZe5EyiBNZQtZ-NenaSR9wTajHXIVkA7ZPExJFrecIucEHBdNKhP8NPLM2DRK_iYknutI_x7j5wwaf2TpJ41IJvKxGG2yUeOGSttetfKe6Ja_DH2ipXCMAPp9hnKVv-3f-TQ7HFZL81ZakAn6qMcCYjHv4sA6pTciF8GGd2ckBh_GiU0VRPUbrp-4JSRe2-eYZB9HMUdTsXNP8c2I61Lg01hkv-dfyl-6P70QAeYTnPEGQFJ-JbkDTT4ceJ-sd_UiTlsj_IXuqOax4apZxeZc_j4EYqEeNV5CFjZvRfEeV9GD2gMwFIRau3ojJ3fRLDHAMkQn1e2ffsc-tsm_ljrcJXPZ07hbvvgecrcy4S7d1D4CaIQmUyuD5jiZxGx30peAcwcteL4ndSVeKw5EGNx4fmUYZW60VbaxZoNVjVPWDiCUAEQUNT9Zl_2tnD1RNqoGrXRCS_Nt1DiQ8HLRe8N29A_cEeeN1bjnQw_v-M1JUI040eMI8eK16mgY9LNPuJ8PC13dMPcsn-qt36PUwsz-Dzm-fgQZFfln4durTd1zPBD1V4HLFxlm00)

</details>

## Project structure

- `docker`: development environment for prototyping. Contains the required dependencies and tools for development,
  but doesn't support eBPF or Tofino switches. Can be used a remote Python interpreter.
- `net_runner`: responsible for compiling the P4 source code and starting a simulated network via Mininet
- `switch`: P4 source code. Configurable constants can be found in a dedicated file.
- `lib_common`: shared library between various Python scripts. Contains constants based on the P4 source code.
- `controller`, `oracle`, `coordinator`: Python implementations of the various components.
  Please refer to the plan overview diagram at the top of this document for more information.
- `centralized`: an alternative controller that executes inference within the Python script as opposed to in-network.
- `trainer`: capable of creating a pre-trained model from data previously collected by other components.
- `pcap_extractor`: extracts flow features and flow data from PCAP files, which can then be used for training a model.
- `training_data`: contains the training data. This data might have to be manually downloaded,
  please refer to the [README.md in the directory](training_data/README.md).
- `work`: working directory, contains automatically generated files.
- `Makefile`: main entry point for this project.
- `tofino-topology.json`: topology definition used when Tofino switches are used.
- `grafana-dashboard.json`: Grafana dashboard definition for visualizing the results of the simulation in real time.
  - Requires InfluxDB 3 with a `natwork-t52` database and the admin token to be set in the `StatsDatabaseConfig` class.

## Installation, setup

- Ensure you have the dependencies listed in [docker/Dockerfile](docker/Dockerfile).
  - Using a docker container is not recommended: some networking and BPF-related features are not expected to work.
- Training data might have to be manually downloaded, please read the [relevant README](training_data/README.md).
- If Tofino switches are used, the Tofino SDE must be installed and configured.

**When editing the P4 source code, make sure to keep `lib_common/data.py` up-to-date.**

## Running

The Makefile can be used to manage the various components of the project.
The file also contains configuration options, which can be modified based on what kind of simulation is desired.

Common commands:

- `make clean`: deletes generated files (e.g. compiled P4 source code), except caches.
- `make clean-all`: deletes all generated files, including caches.

To enable debug logging for any command, append `DEBUG=1` to the command line.
Example: `make mininet-compile DEBUG=1`

### Running with eBPF switches

Commands:

- `make mininet-compile`: compiles the P4 source code and nothing else. Other commands also include this step.
  No recompilation is triggered if no changes are detected in the P4 source directory.
- `make mininet-cli`: starts a simulated network with a CLI, also starting the various project components.
- `make mininet-eval`: rather then starting a CLI, it runs an evaluation that replays a PCAP file.

### Running with Tofino switches

Unlike with the `mininet-eval` command, the individual components must be started manually when using Tofino.

On top of that, the PCAP files might need to be modified to avoid MTU issues.
Example of truncation, including filtering for a specific attack type by only including a specific range of packets:

```shell
editcap -F pcap friday.pcap - 1-5700000 | tcpreplay-edit --mtu=1300 --mtu-trunc --no-flow-stats --fixhdrlen --topspeed -w ddos_and_portscan.pcap -
```

Commands:

- `make tofino-oracle`: starts the oracle component
- `make tofino-coordinator`: starts the controller component
- `make tofino-controller`: starts the controller component
- `make tofino-tcpreplay`: starts packet replaying

### Running with a centralized controller

This controller runs the inference in Python, not in the data plane of the switches.
It can be used with both eBPF and Tofino switches, just set `CENTRALIZED=1` when running the commands.

Prior to starting the centralized controller, a pre-trained model must be created: `make centralized-train`.
This uses data exported by the regular controller component.

## Known issues

- Model encoding sometimes takes a very long time (e.g. even around 30 seconds): the NIKSS-CTL API is very slow.
- A flow started out as benign might become an attacker later.
  Currently, neither our dataset, nor our implementation supports this scenario.

## Long term ideas

There are some ideas that are worth noting, but are not yet planned for implementation.

### Feature (flow property) ideas

- Direction-specific features: e.g. separate feature_count for client-to-server and server-to-client directions.
- Aggregate features: port or IP subnet-based features (e.g. average PPS per port).
  - They should probably be exponential weighted moving averages to keep them relevant for long runtimes.
  - Port-based features require changes to the simulation environment: the ingress IFs from PCAPs must be extracted.

### Evaluation ideas

- Start from a model trained on something, then replay a PCAP file that contains a different attack
- Trick to use multiple CICIDS days at once: replace the 1st byte in the IP addresses with the day's ordinal
- Calculate F1 score or accuracy based on correctly classified packets, not flows:
  - This way the score would reflect how soon the flows get classified
- The oracle should use a random forest model instead of knowing the true labels of the dataset

### Other ideas

- Convert an entire random forest into a single decision tree and encode that into a single match-action table
  - There is literature on this random forest flattening, look into whether it causes the size of the trees to explode
  - We don't need to save the exact certainty values either in this case: all we need to know is whether the certainty
    is above or below the threshold
- Resetting flow data (on flow timeout) could be explicitly synchronizes across switches
  - The switch that adds the inference header determines whether the flow should be timed out
  - It sets a flag in the inference header that indicating its decision

## References, notable papers

Random forest:

- [pForest: In-Network Inference with Random Forests](https://arxiv.org/pdf/1909.05680)
  - RF encoding method: 1 table per depth per tree
- [IIsy: Practical In-Network Classification](https://eng.ox.ac.uk/media/11760/zheng22iisy.pdf)
  - [Source code](https://github.com/In-Network-Machine-Learning/IIsy)
  - RF encoding method: one table per feature + one table per tree
- [Planter: Seeding Trees Within Switches](https://eng.ox.ac.uk/media/9965/zheng21planter.pdf)
  - [Source code](https://github.com/In-Network-Machine-Learning/Planter)
  - RF encoding method: one table per feature + one table per tree
- [Supporting Large Random Forests in the Pipelines of a Hardware Switch to Classify Packets at 100 Gbps Line Rate](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=10274947)
  - RF encoding method: one table per tree
- [SwitchTree: In-network Computing and Traffic Analyses with Random Forests](https://hal.science/hal-02968593v1/document)
  - [Source code](https://github.com/ksingh25/SwitchTree)
  - RF encoding method: one table per depth per tree

Distributed computing & in-network computing:

- [DINC: Toward Distributed In-Network Computing](https://eng.ox.ac.uk/media/f4xdakz0/zheng23dinc.pdf)
  - [Source code](https://github.com/In-Network-Machine-Learning/DINC)
- [Flightplan: Dataplane Disaggregation and Placement for P4 Programs](https://www.usenix.org/system/files/nsdi21spring-sultana.pdf)
- [SRA: Switch Resource Aggregation for Application Offloading in Programmable Networks](https://ieeexplore.ieee.org/document/9322112)

Federated learning:

- [Random forest with differential privacy in federated learning framework for network attack detection and classification](http://www.es.mdu.se/pdf_publications/7023.pdf)
- [Real-Time Detection of DDoS Attacks Based on Random Forest in SDN](https://www.mdpi.com/2076-3417/13/13/7872)
