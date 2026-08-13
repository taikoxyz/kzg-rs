use crate::{
    enums::KzgError, BYTES_PER_FIELD_ELEMENT, BYTES_PER_G1_POINT, BYTES_PER_G2_POINT,
    NUM_G1_POINTS, NUM_G2_POINTS, NUM_ROOTS_OF_UNITY,
};

use crate::bls12_381::{G1Affine, G2Affine, Scalar};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    convert::TryInto,
    hash::{Hash, Hasher},
};
use spin::Once;

fn decode_setup_slice<T, const BYTES_PER_ITEM: usize>(
    bytes: &'static [u8],
    len: usize,
    label: &str,
    mut decode: impl FnMut(&[u8; BYTES_PER_ITEM]) -> T,
) -> &'static [T] {
    assert_eq!(
        bytes.len(),
        len * BYTES_PER_ITEM,
        "invalid trusted setup byte length for {label}"
    );

    let mut values = Vec::with_capacity(len);
    for chunk in bytes.chunks_exact(BYTES_PER_ITEM) {
        values.push(decode(chunk.try_into().expect("checked chunk size")));
    }
    Box::leak(values.into_boxed_slice())
}

pub fn get_roots_of_unity() -> &'static [Scalar] {
    static ROOTS_OF_UNITY: Once<&'static [Scalar]> = Once::new();
    ROOTS_OF_UNITY.call_once(|| {
        let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/roots_of_unity.bin"));
        decode_setup_slice::<Scalar, BYTES_PER_FIELD_ELEMENT>(
            bytes,
            NUM_ROOTS_OF_UNITY,
            "roots_of_unity",
            |bytes| {
                Scalar::from_bytes(bytes)
                    .into_option()
                    .expect("invalid root of unity bytes")
            },
        )
    })
}

pub fn get_g1_points() -> &'static [G1Affine] {
    static G1_POINTS: Once<&'static [G1Affine]> = Once::new();
    G1_POINTS.call_once(|| {
        let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/g1.bin"));
        decode_setup_slice::<G1Affine, BYTES_PER_G1_POINT>(bytes, NUM_G1_POINTS, "g1", |bytes| {
            G1Affine::from_compressed(bytes)
                .into_option()
                .expect("invalid g1 trusted setup bytes")
        })
    })
}

pub fn get_g2_points() -> &'static [G2Affine] {
    static G2_POINTS: Once<&'static [G2Affine]> = Once::new();
    G2_POINTS.call_once(|| {
        let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/g2.bin"));
        decode_setup_slice::<G2Affine, BYTES_PER_G2_POINT>(bytes, NUM_G2_POINTS, "g2", |bytes| {
            G2Affine::from_compressed(bytes)
                .into_option()
                .expect("invalid g2 trusted setup bytes")
        })
    })
}

/// Returns the G2 setup prefix used by KZG proof verification.
///
/// Verification only addresses indices 0 and 1. Keeping this separate from
/// [`get_g2_points`] avoids decoding the remaining setup points in verifier-only
/// programs such as zkVM guests.
pub fn get_g2_verification_points() -> &'static [G2Affine] {
    const VERIFICATION_POINT_COUNT: usize = 2;
    static G2_VERIFICATION_POINTS: Once<&'static [G2Affine]> = Once::new();
    G2_VERIFICATION_POINTS.call_once(|| {
        let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/g2.bin"));
        let bytes = &bytes[..VERIFICATION_POINT_COUNT * BYTES_PER_G2_POINT];
        decode_setup_slice::<G2Affine, BYTES_PER_G2_POINT>(
            bytes,
            VERIFICATION_POINT_COUNT,
            "g2 verification prefix",
            |bytes| {
                G2Affine::from_compressed(bytes)
                    .into_option()
                    .expect("invalid g2 trusted setup bytes")
            },
        )
    })
}

pub fn get_kzg_settings() -> KzgSettings {
    KzgSettings {
        roots_of_unity: get_roots_of_unity(),
        g1_points: get_g1_points(),
        g2_points: get_g2_points(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C, align(4))]
pub struct KzgSettings {
    pub roots_of_unity: &'static [Scalar],
    pub g1_points: &'static [G1Affine],
    pub g2_points: &'static [G2Affine],
}

#[derive(Debug, Clone, Default, Eq)]
pub enum EnvKzgSettings {
    #[default]
    Default,
    Custom(Arc<KzgSettings>),
}

impl PartialEq for EnvKzgSettings {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Default, Self::Default) => true,
            (Self::Custom(a), Self::Custom(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

impl Hash for EnvKzgSettings {
    fn hash<H: Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Self::Default => {}
            Self::Custom(settings) => Arc::as_ptr(settings).hash(state),
        }
    }
}

impl EnvKzgSettings {
    pub fn get(&self) -> &KzgSettings {
        match self {
            Self::Default => {
                static DEFAULT: Once<KzgSettings> = Once::new();
                DEFAULT.call_once(|| {
                    KzgSettings::load_trusted_setup_file()
                        .expect("failed to load default trusted setup")
                })
            }
            Self::Custom(settings) => settings,
        }
    }
}

impl KzgSettings {
    pub fn load_trusted_setup_file() -> Result<Self, KzgError> {
        Ok(get_kzg_settings())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_points_match_full_setup_prefix() {
        let verification_points = get_g2_verification_points();

        assert_eq!(verification_points.len(), 2);
        assert_eq!(verification_points, &get_g2_points()[..2]);
    }
}
