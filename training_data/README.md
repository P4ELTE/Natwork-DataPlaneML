# Data used for training

This document describes the available training data sources and how to obtain them.

The "usage" paragraphs/headings describe how to pass the data sources to the `trainer` Python module.

## CIC-IDS-2017

- Link: https://www.unb.ca/cic/datasets/ids-2017.html
- License: "you should cite our related paper"
- Download: link is at the bottom of the page

Recommended setup:

- Let the day of the dataset you want to use be `<DAY>` (e.g. thursday)
- Download the following files:
  - `CSVs/GeneratedLabelledFlows.zip`: this will contain the selected day's CSV file among others
  - If multiple CSV files exist for the same day, then merge them into a single CSV file (append one after the other)
  - `PCAPs/<DAY>-WorkingHours.pcap`: this is the corresponding PCAP file
- Create a subdirectory under `cicids` for the day: `/training_data/cicids/<DAY>`
- Place (or symlink) the CSV and PCAP files into the directory:
  - CSV filename: `labels.csv`
  - PCAP filename: `features.pcap`
- Some PCAP files contain some flow identifiers multiple times.
  Use [this script](https://gist.github.com/Trigary/b0199ef27a523d42a8786c17544be752) to remove subsequent flows that
  have the same flow ID as a previous flow.

Known issues: see the [Improved CIC-IDS-2017](#improved-cic-ids-2017) section.

## Improved CIC-IDS-2017

- Link: https://intrusion-detection.distrinet-research.be/CNS2022/index.html
- Download: see the "Datasets Download" tab

Recommended setup:

- Download the improved labels
- Download the original PCAP files from the CIC-IDS-2017 dataset
- Place them in the same folder structure as described in the original CIC-IDS-2017 section
- Run [pcapfix](https://f00l.de/pcapfix/) and [reorderpcap](https://www.wireshark.org/docs/man-pages/reordercap.html)
  on the downloaded PCAP files
  - `pcapfix` doesn't seem to detect any issues, so either I am using the tool incorrectly or running it is not needed
- Follow any extra steps described in the original CIC-IDS-2017 section
  - E.g. remove duplicate flows

## Other datasets

Several other datasets have been considered, found. Below is the notes on them.
Unfortunately this list is not organized in any way, it's just a collection of quick notes.

- List: https://www.informatik.uni-wuerzburg.de/datascience/research/datasets/nids-ds/
- CIC list: https://www.unb.ca/cic/datasets/index.html
- https://research.unsw.edu.au/projects/unsw-nb15-dataset
  - lots of flow collisions: lot of traffic doesn't even use protocol ports, so naturally the IPs collide
  - other people in NATWORK use this, as an alternative to CIC-IDS-2017
- https://www.stratosphereips.org/datasets-ctu13
  - other people in NATWORK use this, as an alternative to CIC-IDS-2017
  - I haven't looked into it yet
- TON-IOT
  - There are tons of PCAP files and tons of CSVs
  - the CSVs aren't in the same format, but maybe I was just looking at the wrong folder (same folder as the PCAPs)
- UNIBS-2009
- https://www.unb.ca/cic/datasets/iotdataset-2022.html
- http://205.174.165.80/IOTDataset/CIC_IOT_Dataset2022/Dataset/
  - Only two types of attacks: flood and RTSP-Brute Force
- https://www.unb.ca/cic/datasets/iotdataset-2023.html
  - several hundred GBs of PCAPs
- Edge-IIoT
- 5G-NIDD

A lot of datasets contain very large PCAPs, which cannot be used directly (one or more files of 100GB+).
Multiple datasets contain IP-based attacks that target e.g. IP buffer overflow exploits.
We might have a hard time training for such attacks, as almost all flows will have the same flow ID, therefore we
would need to classify packets based on when they were sent, which is not possible with the current setup.
