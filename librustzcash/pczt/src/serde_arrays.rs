//! Serde tuple encodings for PCZT's fixed-length byte arrays.
//!
//! Arrays use tuples rather than byte strings so their encodings have no
//! length prefix. These adapters also support optional arrays and map keys.

use alloc::collections::BTreeMap;
use core::{fmt, marker::PhantomData};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error, MapAccess, SeqAccess, Visitor},
    ser::SerializeTuple,
};

pub(super) fn serialize<S, const N: usize>(
    value: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut tuple = serializer.serialize_tuple(N)?;
    for byte in value {
        tuple.serialize_element(byte)?;
    }
    tuple.end()
}

pub(super) fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    struct ArrayVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for ArrayVisitor<N> {
        type Value = [u8; N];

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "an array of size {N}")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut array = [0; N];
            for (index, byte) in array.iter_mut().enumerate() {
                *byte = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(index, &self))?;
            }
            Ok(array)
        }
    }

    deserializer.deserialize_tuple(N, ArrayVisitor::<N>)
}

/// Adapts a borrowed array for serialization or an owned one for parsing.
struct Array<T>(T);

impl<const N: usize> Serialize for Array<&[u8; N]> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize(self.0, serializer)
    }
}

impl<'de, const N: usize> Deserialize<'de> for Array<[u8; N]> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize(deserializer).map(Self)
    }
}

pub(super) fn serialize_option<S, const N: usize>(
    value: &Option<[u8; N]>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    value.as_ref().map(Array).serialize(serializer)
}

pub(super) fn deserialize_option<'de, D, const N: usize>(
    deserializer: D,
) -> Result<Option<[u8; N]>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Array<[u8; N]>>::deserialize(deserializer).map(|value| value.map(|Array(array)| array))
}

pub(super) fn serialize_map<S, V, const N: usize>(
    value: &BTreeMap<[u8; N], V>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    V: Serialize,
{
    serializer.collect_map(value.iter().map(|(key, value)| (Array(key), value)))
}

pub(super) fn deserialize_map<'de, D, V, const N: usize>(
    deserializer: D,
) -> Result<BTreeMap<[u8; N], V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    struct ArrayMapVisitor<V, const N: usize>(PhantomData<V>);

    impl<'de, V, const N: usize> Visitor<'de> for ArrayMapVisitor<V, N>
    where
        V: Deserialize<'de>,
    {
        type Value = BTreeMap<[u8; N], V>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a map")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut values = BTreeMap::new();
            while let Some((Array(key), value)) = map.next_entry::<Array<[u8; N]>, V>()? {
                values.insert(key, value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_map(ArrayMapVisitor::<V, N>(PhantomData))
}
