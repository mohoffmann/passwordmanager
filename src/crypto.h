#pragma once
#include <optional>
#include <string>
#include <vector>

using Bytes = std::vector<unsigned char>;

// Returns the derived key, or nothing if key derivation failed
std::optional<Bytes> derive_key(const std::string& passwd, const Bytes& salt);

// Returns nonce + ciphertext + tag
Bytes encrypt(const Bytes& key, const Bytes& plaintext);

// Returns the plaintext, or nothing if the password was wrong or the data was tampered with
std::optional<Bytes> decrypt(const Bytes& key, const Bytes& cypher);

// Returns crypto_pwhash_SALTBYTES random bytes
Bytes generate_salt();