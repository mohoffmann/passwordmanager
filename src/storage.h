#pragma once
#include <optional>
#include <string>
#include "crypto.h"   // for Bytes

// What is stored in the vault file, after the header
struct VaultFile {
    Bytes salt;   // for derive_key
    Bytes blob;   // nonce + ciphertext + tag, as returned by encrypt
};

std::string default_vault_path();

// True if something exists at this path (even a broken file or a symlink)
bool vault_exists(const std::string& path);

// Writes the vault file: creates the directory (0700) if needed, writes a temp
// file (0600) and renames it over the real one. Returns false on any failure
bool write_vault(const std::string& path, const Bytes& salt, const Bytes& blob);

// Reads and checks the vault file. Returns nothing if the file is missing, not a
// regular file, a symlink, too small, too large or has the wrong header
std::optional<VaultFile> read_vault(const std::string& path, size_t salt_len);