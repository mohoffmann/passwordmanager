#include "crypto.h"
#include <sodium.h>

Bytes generate_salt() {
    Bytes salt(crypto_pwhash_SALTBYTES);      // vector of the right size, filled with zeros
    randombytes_buf(salt.data(), salt.size()); // overwrite it with random bytes
    return salt;
}

std::optional<Bytes> derive_key(const std::string& passwd, const Bytes& salt) {
    if (salt.size() != crypto_pwhash_SALTBYTES) {
        return std::nullopt;                  // wrong size: libsodium would read past the end
    }

    Bytes key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

    int rc = crypto_pwhash(
        key.data(), key.size(),               // out, outlen
        passwd.data(), passwd.size(),         // passwd, passwdlen
        salt.data(),                          // salt
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_ARGON2ID13);

    if (rc != 0) {
        return std::nullopt;                  // e.g. out of memory
    }
    return key;                               // C++ puts it in the optional
}

Bytes encrypt(const Bytes& key, const Bytes& plaintext) {
    const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const size_t tag_len   = crypto_aead_xchacha20poly1305_ietf_ABYTES;

    Bytes out(nonce_len + plaintext.size() + tag_len);

    // nonce goes into the first nonce_len bytes of out
    randombytes_buf(out.data(), nonce_len);

    // ciphertext + tag is written right after the nonce
    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        out.data() + nonce_len, &clen,
        plaintext.data(), plaintext.size(),
        nullptr, 0,          // no additional data
        nullptr,             // nsec is unused
        out.data(),          // the nonce we just wrote
        key.data());

    return out;
}

std::optional<Bytes> decrypt(const Bytes& key, const Bytes& data) {
    const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const size_t tag_len   = crypto_aead_xchacha20poly1305_ietf_ABYTES;

    if (data.size() < nonce_len + tag_len) {
        return std::nullopt;                 // too short to be valid
    }

    const unsigned char* nonce      = data.data();
    const unsigned char* ciphertext = data.data() + nonce_len;
    const size_t clen               = data.size() - nonce_len;

    Bytes plaintext(clen - tag_len);
    unsigned long long mlen = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &mlen,
            nullptr,                         // nsec is unused
            ciphertext, clen,
            nullptr, 0,                 // no additional data
            nonce,
            key.data()) != 0) {
        return std::nullopt;                 // wrong key or modified data
    }

    plaintext.resize(mlen);
    return plaintext;
}
