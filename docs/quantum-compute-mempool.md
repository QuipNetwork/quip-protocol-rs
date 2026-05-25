# Quantum Compute Mempool

## Canonical Plain Ising Job Spec

`QuantumComputeMempool` seeds a default plain Ising job spec at genesis so SDKs
can call `propose_job` without first registering a spec.

Canonical tuple:

```text
name = "plain-ising-v1"
formulation = Ising
validation_program = None
transform_program = None
```

The `spec_id` is the runtime hash of the SCALE-encoded tuple:

```text
(name, formulation, validation_program, transform_program)
```

Pinned `spec_id`:  
NOTE: This value is verified by CI (default_ising_spec_id_is_pinned and default_ising_spec_id_matches_pinned_hash);
if any tuple field changes, those tests will fail.

```text
0x8f46f3a31321d1d093314fc769c42cbe7a83d71a0b69e6571a0f68e2a04067f0
```

SDKs may hardcode this value or read the `DefaultIsingSpecId` pallet constant
from metadata. Additional job specs are team-controlled: `register_job_spec`
requires root origin and records an explicit builder account supplied by root.
