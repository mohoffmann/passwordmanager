#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <termios.h>
#include <unistd.h>
#include <sodium.h>

#include "crypto.h"
#include "storage.h"
#include "vault.h"

static const size_t MIN_MASTER_LEN = 8;     // shortest master password we accept
static const int CLIPBOARD_SECONDS = 30;    // how long a copied password stays in the clipboard
static const char* UNLOCK_FAILED = "Unlock failed: wrong master password or damaged vault.";

// Everything we hold in memory while the vault is unlocked
struct Session {
    Bytes key;      // derived from the master password, never written to disk
    Bytes salt;     // stored in the vault file
    Vault vault;    // name -> password, decrypted
};

// sodium_memzero is not optimized away by the compiler (a plain memset can be).
static void wipe(Bytes& b)       { if (!b.empty()) sodium_memzero(b.data(), b.size()); }
static void wipe(std::string& s) { if (!s.empty()) sodium_memzero(&s[0], s.size()); }

// Reads one line without showing what is typed, Echo is switched off
static std::string read_secret(const std::string& prompt) {
    termios old_settings;
    bool is_terminal = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &old_settings) == 0;
    if (is_terminal) {
        termios no_echo = old_settings;
        no_echo.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &no_echo);
    }
    std::cout << prompt << std::flush;

    std::string line;
    std::getline(std::cin, line);

    if (is_terminal) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_settings);
        std::cout << "\n";   // the Enter key was not echoed
    }
    return line;
}

static bool save(const std::string& path, const Session& s) {
    return write_vault(path, s.salt, encrypt(s.key, serialize(s.vault)));
}

// The commands are fixed strings (nothing the user typed goes into them), The password
// is sent through a pipe, so it never shows up in `ps`
struct ClipboardTool {
    const char* env_var;     // set when this kind of desktop session is running
    const char* copy_cmd;
    const char* clear_cmd;
};
static const ClipboardTool TOOLS[] = {
    {"WAYLAND_DISPLAY", "wl-copy >/dev/null 2>&1", "wl-copy --clear"},
    {"DISPLAY", "xclip -selection clipboard >/dev/null 2>&1",
                "printf '' | xclip -selection clipboard"},
};

static bool copy_to_clipboard(const std::string& text) {
    std::signal(SIGPIPE, SIG_IGN);   // a missing tool must not kill us when we write to it
    for (const ClipboardTool& tool : TOOLS) {
        if (std::getenv(tool.env_var) == nullptr) continue;

        FILE* pipe = popen(tool.copy_cmd, "w");
        if (pipe == nullptr) continue;
        size_t written = std::fwrite(text.data(), 1, text.size(), pipe);
        int status = pclose(pipe);   // 0 = the tool ran and succeeded
        if (written != text.size() || status != 0) continue;

        // Empty the clipboard later, from a background shell that outlives this program
        std::string clear = "(sleep " + std::to_string(CLIPBOARD_SECONDS) + "; " +
                            tool.clear_cmd + ") >/dev/null 2>&1 </dev/null &";
        std::system(clear.c_str());
        return true;
    }
    return false;
}

// First run: no vault file yet. Ask for a new master password and create an empty vault.
static std::optional<Session> create_new(const std::string& path) {
    std::cout << "No vault found. Creating a new one at " << path << "\n";
    std::string first = read_secret("New master password: ");
    std::string again = read_secret("Repeat master password: ");
    if (first != again) {
        std::cerr << "The passwords do not match.\n";
        return std::nullopt;
    }
    if (first.size() < MIN_MASTER_LEN) {
        std::cerr << "The master password must be at least " << MIN_MASTER_LEN << " characters.\n";
        return std::nullopt;
    }

    Session s;
    s.salt = generate_salt();
    auto key = derive_key(first, s.salt);
    wipe(first);
    wipe(again);
    if (!key) {
        std::cerr << "Key derivation failed.\n";
        return std::nullopt;
    }
    s.key = *key;
    if (!save(path, s)) {
        std::cerr << "Could not write the vault file.\n";
        return std::nullopt;
    }
    return s;
}

static std::optional<Session> unlock_failed() {
    std::cerr << UNLOCK_FAILED << "\n";   // the same message for every kind of failure
    return std::nullopt;
}

// Later runs: the vault opens only if decryption works. A wrong password, a changed
// file and a damaged file all end up in unlock_failed()
static std::optional<Session> unlock(const std::string& path) {
    std::string master = read_secret("Master password: ");

    auto file = read_vault(path, crypto_pwhash_SALTBYTES);
    if (!file) {
        wipe(master);
        return unlock_failed();
    }
    auto key = derive_key(master, file->salt);
    wipe(master);
    if (!key) return unlock_failed();

    auto plain = decrypt(*key, file->blob);      // fails if the password is wrong or the file changed
    if (!plain) return unlock_failed();
    auto vault = deserialize(*plain);
    wipe(*plain);
    if (!vault) return unlock_failed();

    return Session{*key, file->salt, *vault};
}

static void run_shell(Session& s, const std::string& path) {
    std::string line;
    while (true) {
        std::cout << "pwmanager> " << std::flush;
        if (!std::getline(std::cin, line)) break;   // Ctrl+D or end of input

        std::istringstream words(line);
        std::string cmd, name;
        words >> cmd;
        std::getline(words >> std::ws, name);       // the rest of the line is the name

        if (cmd.empty()) continue;
        if (cmd == "exit") break;
        if ((cmd == "add" || cmd == "get" || cmd == "delete") && name.empty()) {
            std::cout << "Usage: " << cmd << " <name>\n";   // an empty name would break the vault format
            continue;
        }

        if (cmd == "list") {
            for (const auto& entry : s.vault) std::cout << entry.first << "\n";   // names only
        } else if (cmd == "add") {
            if (s.vault.count(name) != 0) {
                std::cout << "'" << name << "' already exists. Delete it first.\n";
                continue;
            }
            std::string pw = read_secret("Password: ");
            std::string again = read_secret("Repeat password: ");
            if (pw.empty() || pw != again) {
                std::cout << "Empty or different passwords. Nothing was added.\n";
            } else {
                s.vault[name] = pw;
                std::cout << (save(path, s) ? "Added.\n" : "Could not save the vault.\n");
            }
            wipe(pw);
            wipe(again);
        } else if (cmd == "get") {
            auto it = s.vault.find(name);
            if (it == s.vault.end()) {
                std::cout << "No entry '" << name << "'.\n";
            } else if (copy_to_clipboard(it->second)) {
                std::cout << "Copied to the clipboard. It is cleared in " << CLIPBOARD_SECONDS << " seconds.\n";
            } else {
                std::cout << "No clipboard tool found. Install wl-clipboard (Wayland) or xclip (X11).\n"
                             "The password is not printed.\n";
            }
        } else if (cmd == "delete") {
            if (s.vault.erase(name) == 0) {
                std::cout << "No entry '" << name << "'.\n";
            } else {
                std::cout << (save(path, s) ? "Deleted.\n" : "Could not save the vault.\n");
            }
        } else {
            std::cout << "Unknown command. Use: add <name>, get <name>, list, delete <name>, exit\n";
        }
    }
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Could not initialize libsodium.\n";
        return 1;
    }
    std::string path = default_vault_path();
    if (path.empty()) {
        std::cerr << "Cannot find the vault location (HOME is not set).\n";
        return 1;
    }

    std::optional<Session> session = vault_exists(path) ? unlock(path) : create_new(path);
    if (!session) return 1;

    run_shell(*session, path);

    wipe(session->key);                                     // the key leaves memory on exit
    for (auto& entry : session->vault) wipe(entry.second);  // and so do the passwords
    return 0;
}