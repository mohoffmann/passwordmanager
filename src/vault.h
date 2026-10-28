#pragma once
#include <map>
#include <optional>
#include <string>
#include "crypto.h"   // for Bytes

using Vault = std::map<std::string, std::string>;   // name -> password

// Turns the vault into bytes, ready to encrypt
Bytes serialize(const Vault& v);

// Turns bytes back into a vault, or nothing if the bytes are malformed
std::optional<Vault> deserialize(const Bytes& data);