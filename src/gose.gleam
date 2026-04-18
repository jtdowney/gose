//// A Gleam library for JOSE (JSON Object Signing and Encryption) and
//// COSE (CBOR Object Signing and Encryption).
////
//// Core:
//// - `gose/algorithm`: algorithm identifiers
//// - `gose/key`: key management
//// - `gose/cbor`: CBOR encoding for COSE
////
//// JOSE:
//// - `gose/jose/jws`: JSON Web Signature ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html))
//// - `gose/jose/jws_multi`: JWS JSON Serialization for multi-signer workflows
//// - `gose/jose/jwe`: JSON Web Encryption ([RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html))
//// - `gose/jose/jwe_multi`: JWE JSON Serialization for multi-recipient workflows
//// - `gose/jose/jwk`: JSON Web Key serialization ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html))
//// - `gose/jose/key_set`: JWK Set ([RFC 7517 Section 5](https://www.rfc-editor.org/rfc/rfc7517.html#section-5))
//// - `gose/jose/encrypted_key`: encrypted JWK export/import
//// - `gose/jose/jwt`: JSON Web Token ([RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html))
//// - `gose/jose/encrypted_jwt`: encrypted JWT (JWE-based)
////
//// COSE:
//// - `gose/cose`: header parameters ([RFC 9052 Section 3.1](https://www.rfc-editor.org/rfc/rfc9052.html#section-3.1))
//// - `gose/cose/sign1`: COSE_Sign1 ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html))
//// - `gose/cose/sign`: COSE_Sign multi-signer ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html))
//// - `gose/cose/encrypt0`: COSE_Encrypt0 ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html))
//// - `gose/cose/encrypt`: COSE_Encrypt multi-recipient ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html))
//// - `gose/cose/mac0`: COSE_Mac0 ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html))
//// - `gose/cose/key`: COSE Key serialization ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html))
//// - `gose/cose/algorithm`: COSE algorithm ID mapping ([RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html))
//// - `gose/cose/cwt`: CBOR Web Token ([RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html))
//// - `gose/cose/encrypted_cwt`: encrypted CWT (Encrypt0-wrapped Sign1)

/// Error type for JOSE and COSE operations.
///
/// Used by low-level JOSE/COSE primitives. The JWT and CWT layers wrap these
/// errors in their own domain-specific variants for token validation.
pub type GoseError {
  /// Parsing failed: invalid base64, malformed JSON, unexpected structure, etc.
  /// The `String` provides a human-readable description of what went wrong.
  ParseError(String)
  /// A cryptographic operation failed: signature verification, decryption,
  /// key derivation, etc. The `String` describes the failure.
  CryptoError(String)
  /// An operation was attempted in an invalid state: wrong key type for the
  /// chosen algorithm, missing required header field, etc. The `String`
  /// explains which invariant was violated.
  InvalidState(String)
  /// Signature or MAC verification failed. Intentionally carries no detail
  /// to avoid leaking information that could enable oracle attacks.
  VerificationFailed
}

/// Extract the message string from a GoseError, regardless of variant.
pub fn error_message(error: GoseError) -> String {
  case error {
    ParseError(msg) -> msg
    CryptoError(msg) -> msg
    InvalidState(msg) -> msg
    VerificationFailed -> "verification failed"
  }
}
