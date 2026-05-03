# ZK Circuit Soundness Review — Plonkish Proof System

## Scope

Soundness audit of a custom Plonkish circuit implementing private state
transitions over BN254 curve.

- Custom gates
- Lookup tables (Plookup)
- Copy constraints
- Verifier contract

## Methodology

- Constraint completeness and soundness analysis
- Witness generation verification across edge cases
- Custom gate degree and selector review
- Lookup argument correctness verification

## Findings

### Critical Severity (1)

| ID | Title | Description |
|---|---|---|
| C-01 | Under-constrained custom gate | Missing selector polynomial activation on boundary condition allows invalid witness assignment that passes verification. Attacker can skip transition gate by setting s_transition = 0 while still modifying state advice columns. |

### Medium Severity (2)

| ID | Title | Description |
|---|---|---|
| M-01 | Incomplete range check in lookup table | range_check_table only covers [0, 2^16) but advice column can hold values up to p-1 on BN254 |
| M-02 | Copy constraint gap | Missing copy constraint between advice and instance columns allows witness inconsistency |

## Stack

Halo2, Rust, BN254, Plonkish arithmetization

## Disclaimer

This is a sample audit report demonstrating methodology and report format.
