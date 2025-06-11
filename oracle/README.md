# Flow classifier oracle overview

The purpose of this component is to classify flows based on their features (and possible related data such as flow ID).
The classification results are used to measure the performance of the in-network classification and to improve the
classification model being used. Therefore, the oracle must be better at classification than the in-network classifier.

## Logic implementations

The oracle can be implemented in many ways. The Python process might classify flows itself, or it might manage
a separate classifier process, or make use of a remote classifier service. All variants share the same interface.
The following variants have been implemented:

### Label-CSV mock logic

This implementation associated flow IDs with their labels by reading this data from a CSV file.
This implementation is unable to classify flows that are not present in the CSV file.

The implementation uses a single thread: it listens for incoming flow classification requests,
looks up the appropriate label, and sends the result back.
