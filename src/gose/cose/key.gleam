//// Deprecated: use the `gose/cose` module instead.
////
//// This module is a shim that forwards the COSE_Key serialization
//// surface to `gose/cose`. It will be removed in v3.0.

import gose
import gose/cbor
import gose/cose

@deprecated("use gose/cose.Key")
pub type Key =
  gose.Key(BitArray)

@deprecated("use gose/cose.key_to_cbor")
pub fn to_cbor(k: gose.Key(BitArray)) -> Result(BitArray, gose.GoseError) {
  cose.key_to_cbor(k)
}

@deprecated("use gose/cose.key_from_cbor")
pub fn from_cbor(data: BitArray) -> Result(gose.Key(BitArray), gose.GoseError) {
  cose.key_from_cbor(data)
}

@deprecated("use gose/cose.key_to_cbor_map")
pub fn to_cbor_map(
  k: gose.Key(BitArray),
) -> Result(List(#(cbor.Value, cbor.Value)), gose.GoseError) {
  cose.key_to_cbor_map(k)
}

@deprecated("use gose/cose.key_from_cbor_map")
pub fn from_cbor_map(
  map: List(#(cbor.Value, cbor.Value)),
) -> Result(gose.Key(BitArray), gose.GoseError) {
  cose.key_from_cbor_map(map)
}
