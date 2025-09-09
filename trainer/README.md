# Trainer overview

This component can create a pre-trained model from the provided data.
Different constraints can be selected based on the use case for the trained model:
deployment to a switch or usage in the centralized component.

The data used for training is collected by the `controller` component
or the `pcap_extractor` component in the form of a `.npz` file.

Please keep in mind that various controller configuration options influence which flows get included in the file:

- The value of `max_of_flow_time_window_sec` determines how old flows can be before they are forgotten.
  Forgotten flows are not included in the file.
- The value of `stats_from_all_flows` determines whether flows should be collected even if they are not used
  for model re-training.
