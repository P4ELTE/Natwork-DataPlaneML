# Coordinator overview

This component is responsible for connecting multiple network domains (controllers).
Controllers share their locally-trained models with the coordinator,
which aggregates them and trains a global model (i.e. federated learning).
The global model is sent to each controller, which slices it into smaller pieces and uploads it to its switches.

TODO Currently, the coordinator just sends back the model it receives: it does neither model aggregation nor slicing.
