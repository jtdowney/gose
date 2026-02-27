//// A Gleam JOSE (JSON Object Signing and Encryption) library.
////
//// - `gose/jwa` — Algorithm identifiers ([RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html))
//// - `gose/jwe` — Encryption ([RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html))
//// - `gose/jwk` — Key management ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html))
//// - `gose/jws` — Digital signatures ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html))
//// - `gose/jwt` — JSON Web Tokens ([RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html))
////
//// This module defines `GoseError`, the shared error type for JWS, JWE, and JWK.
//// The JWT layer has its own `JwtError` with richer domain-specific variants.

/// Error type for JOSE primitive operations (JWS, JWE, JWK).
///
/// This is the error type used by low-level JOSE modules. The JWT layer
/// wraps this via `JwtError.JoseError` to provide richer domain-specific
/// error variants for token validation.
pub type GoseError {
  /// Parsing failed - invalid base64, malformed JSON, unexpected structure, etc.
  /// The `String` provides a human-readable description of what went wrong.
  ParseError(String)
  /// A cryptographic operation failed - signature verification, decryption,
  /// key derivation, etc. The `String` describes the failure.
  CryptoError(String)
  /// An operation was attempted in an invalid state - wrong key type for the
  /// chosen algorithm, missing required header field, etc. The `String`
  /// explains which invariant was violated.
  InvalidState(String)
}

/// Extract the message string from a GoseError, regardless of variant.
///
/// ## Parameters
///
/// - `error` - The error to extract the message from.
///
/// ## Returns
///
/// The human-readable description string contained in the error variant.
pub fn error_message(error: GoseError) -> String {
  case error {
    ParseError(msg) -> msg
    CryptoError(msg) -> msg
    InvalidState(msg) -> msg
  }
}
