# P4 source code

This folder contains the P4 source code of the switches.

The `debug` folder contains various small P4 programs that were used for debugging purposes.

The `psa` and `tofino` folders contain the actual switch implementation, for the different architectures.

The `centralized` variants are for the control plane component named `centralized`,
which doesn't use in-network inference.
The regular `controller` control plane component uses in-network inference.
