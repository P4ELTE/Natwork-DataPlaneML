# Controller overview

The controller is the central component of the network domains.
Controllers have various responsibilities:

- Configuring switches to achieve basic packet forwarding
- Uploading traffic classification models to switches
- Monitoring the switches to detect loss of classification performance
- Refining the models to improve performance
- Sharing improved models with the coordinator
- Receiving updated models from the coordinator

## Threads

Multiple threads and processes are utilized in the controller implementation.

Python threads are used whenever necessary to avoid the complexity overhead of inter-process communication:
some of the threads need to share data, and mutexes are sufficient to ensure data integrity.
Multiprocessing is rarely necessary, as the controller is not CPU-bound: threads are usually waiting for I/O.

The following threads are used:

- Thread A (Main thread):
  - Listens for model updates from the coordinator
  - Periodically sends the new flows to the oracle for classification
  - If the data plane classifier's performance is below a threshold,
    refines the model and shares the updated model with the coordinator
- Thread B: listens for report packets from switches and processes them
- Process 2: helps thread B by listening for report packets and preprocessing them
  - A separate process is used to avoid workload spikes on the "main process" to cause the packet processing to fall
  behind, potentially causing packet loss due to buffer overflows or just latency due to buffer saturation

## Encoding random forests to the data plane

A separate random forest encoding method is used for eBPF and Tofino switches.
In both cases, the encoding process consists of the following main steps:

- A new model is created and RF IDs are assigned to the forests that are not already in use in the data plane
- A flow length -> RF ID mapping is used within the data plane, allowing various flow lengths to share the same RF,
  potentially reducing memory usage
- The new model is uploaded to the switches while the old model is still being used
  - For this reason, we require twice as much memory as the largest supported model requires
- Finally, the flow length -> RF ID mapping is updated to point to the new model
- Optionally extra cleanup is done to remove the old model from the switches

This process guarantees seamless updates of the model in the data plane within singular switches.
To achieve atomicity across multiple switches, it's important to mark each packet with the RF ID of the model that
should be used for that specific model: the first switch that interacts with the packet should save this RF ID.

## Report packets

Switches send report packets to the control plane. The control plane uses them packet for multiple purposes:

- Monitoring the performance of the data plane classifier.
- Refining the model if the performance is below a threshold.

For simplicity, we do not have a separate evaluation Python module, but rather the controller is used for evaluation.
For this reason, all flows are forwarded to the control plane, but the control plane only uses a small portion of these
flows (e.g. 5%) for model refining and performance monitoring. The rest of the flows are exclusively saved for
statistics and are only used for creating plots.

The data from the report packets becomes available to higher level functions (e.g. model refinement) in 2 possible ways:

- The flow times out or the flow reaches the maximum flow length (packet count), whichever comes first.
- The flow is still ongoing, so only the first few packets of the flow are available.

It's important to note that the oracle might not support the 2nd option, as it may not be able to classify flows
that are not complete.
