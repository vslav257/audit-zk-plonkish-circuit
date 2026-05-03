// circuit.rs — Custom Plonkish circuit for private state transitions
// Audit: C-01 (Critical), M-01, M-02
// Stack: Halo2, BN254, Plookup

use halo2_proofs::{
    circuit::{Layouter, Value, SimpleFloorPlanner},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error,
        Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};

#[derive(Clone, Debug)]
struct StateTransitionConfig {
    advice: [Column<Advice>; 5],
    instance: Column<Instance>,
    s_enable: Selector,
    s_transition: Selector,        // C-01: missing activation
    q_lookup: Selector,
    range_check_table: Column<Fixed>,
}

struct StateTransitionChip {
    config: StateTransitionConfig,
}

impl StateTransitionChip {
    fn configure(
        meta: &mut ConstraintSystem<Fp>,
    ) -> StateTransitionConfig {
        let advice = [(); 5].map(|_| meta.advice_column());
        let instance = meta.instance_column();
        let s_enable = meta.selector();
        let s_transition = meta.selector();
        let q_lookup = meta.selector();
        let range_check_table = meta.fixed_column();

        // C-01: CRITICAL — Under-constrained custom gate
        // BUG: s_transition selector is NOT constrained to be
        // active when state change occurs. Attacker can skip
        // transition gate by setting s_transition = 0 while
        // still modifying state advice columns.
        //
        // Expected: s_transition should be enforced via:
        //   meta.create_gate("enforce_transition", |meta| {
        //       let s = meta.query_selector(s_enable);
        //       let s_t = meta.query_selector(s_transition);
        //       vec![s * (Expression::Constant(Fp::one()) - s_t)]
        //       // ^ this constraint is MISSING
        //   });
        //
        // Impact: invalid witness passes verification.
        // Attacker sets old_state = new_state arbitrarily,
        // bypasses transition validity check entirely.

        meta.create_gate("state_transition", |meta| {
            let s = meta.query_selector(s_transition);
            let old_state = meta.query_advice(advice[0], Rotation::cur());
            let new_state = meta.query_advice(advice[1], Rotation::cur());
            let delta = meta.query_advice(advice[2], Rotation::cur());
            let range_proof = meta.query_advice(advice[3], Rotation::cur());

            vec![
                // Constraint: delta == new_state - old_state
                s.clone() * (old_state.clone() + delta.clone()
                    - new_state.clone()),
                // Constraint: range check on delta
                s * (delta.clone() * (delta - Expression::Constant(Fp::one()))
                    * range_proof
                    - Expression::Constant(Fp::one())),
            ]
        });

        // M-01: Lookup table range check incomplete
        // BUG: range_check_table only covers [0, 2^16)
        // but advice[2] (delta) can hold values up to p-1
        // on BN254. Missing range gate for full field coverage.
        meta.lookup("range_check", |meta| {
            let q = meta.query_selector(q_lookup);
            let value = meta.query_advice(advice[2], Rotation::cur());
            vec![(q * value, range_check_table)]
        });

        StateTransitionConfig {
            advice, instance, s_enable,
            s_transition, q_lookup, range_check_table,
        }
    }

    fn assign_transition(
        &self,
        mut layouter: impl Layouter<Fp>,
        old_state: Value<Fp>,
        new_state: Value<Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "state transition",
            |mut region| {
                self.config.s_transition.enable(&mut region, 0)?;
                self.config.q_lookup.enable(&mut region, 0)?;

                region.assign_advice(
                    || "old_state",
                    self.config.advice[0],
                    0,
                    || old_state,
                )?;

                region.assign_advice(
                    || "new_state",
                    self.config.advice[1],
                    0,
                    || new_state,
                )?;

                region.assign_advice(
                    || "delta",
                    self.config.advice[2],
                    0,
                    || new_state - old_state,  // BUG: attacker controls witness
                )?;

                Ok(())
            },
        )
    }
}
