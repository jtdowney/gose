import gose
import unitest

pub fn main() -> Nil {
  unitest.run(
    unitest.Options(
      ..unitest.default_options(),
      execution_mode: unitest.RunAsync,
    ),
  )
}

pub fn error_message_parse_error_test() {
  assert gose.error_message(gose.ParseError("bad input")) == "bad input"
}

pub fn error_message_crypto_error_test() {
  assert gose.error_message(gose.CryptoError("decrypt failed"))
    == "decrypt failed"
}

pub fn error_message_invalid_state_test() {
  assert gose.error_message(gose.InvalidState("wrong key type"))
    == "wrong key type"
}
