#include "vault.h"
#include <sstream>

Bytes serialize(const Vault& v) {
    std::string text;
    for (const auto& [name, pw] : v) {   // one pass per entry in the map
        text += name;
        text += '\n';
        text += pw;
        text += '\n';
    }
    return Bytes(text.begin(), text.end());   // copy the characters into a Bytes
}

std::optional<Vault> deserialize(const Bytes& data) {
    std::istringstream in(std::string(data.begin(), data.end()));
    Vault v;
    std::string name, pw;

    while (std::getline(in, name)) {          // read one line: the name
        if (name.empty()) {
            return std::nullopt;              // an entry without a name is malformed
        }
        if (!std::getline(in, pw)) {          // the line after it must exist: the password
            return std::nullopt;              // name with no password: malformed
        }
        v[name] = pw;
    }
    return v;
}