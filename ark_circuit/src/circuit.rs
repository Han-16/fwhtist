pub use ark_ec::CurveGroup;
pub use ark_ff::{Field, PrimeField};
pub use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
pub use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
pub use ark_serialize::CanonicalSerialize;
pub use ark_std::marker::PhantomData;

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[derive(Clone, Debug)]
pub struct AggKZGInstances<C: CurveGroup> {
    pub random_scalars: Vec<C::BaseField>,
    // pub indices: Vec<usize>,
    pub y: C::Affine,
    pub commitments: C::BaseField,
}


#[derive(Clone, Debug)]
pub struct AggKZGWitness<C: CurveGroup> {
    pub group_points: Vec<C::Affine>,
}

#[derive(Clone)]
pub struct AggKZGCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    <C as CurveGroup>::BaseField: PrimeField,
{
    pub instance: AggKZGInstances<C>,
    pub witness: AggKZGWitness<C>,
    pub _curve: PhantomData<GG>,
}

impl<C, GG> ConstraintSynthesizer<C::BaseField> for AggKZGCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> ark_relations::r1cs::Result<()> {
        // instances
        let random_scalars_var = Vec::<FpVar<C::BaseField>>::new_input(cs.clone(), || {
            Ok(self.instance.random_scalars)
        })?;
        let y_var = GG::new_input(cs.clone(), || {
            Ok(self.instance.y)
        })?;
        let commitments_var = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            Ok(self.instance.commitments)
        })?;

        // witness
        let group_points_var = Vec::<GG>::new_witness(cs.clone(), || {
            Ok(self.witness.group_points)
        })?;

        // constraints
        

        Ok(())
    }
}
