#include "storage.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static const char MAGIC[4] = {'P', 'W', 'V', '1'};
static const size_t MAX_FILE_SIZE = 16 * 1024 * 1024;   // refuse files bigger than 16 MiB

std::string default_vault_path() {
    const char* home = std::getenv("HOME");
    if (home == nullptr || home[0] == '\0') return "";
    return std::string(home) + "/.pwmanager/vault.pwvault";
}

bool vault_exists(const std::string& path) {
    struct stat st;
    return lstat(path.c_str(), &st) == 0;   // lstat does not follow symlinks
}

bool write_vault(const std::string& path, const Bytes& salt, const Bytes& blob) {
    // 1. The directory: owner only. EEXIST just means it is already there
    size_t slash = path.rfind('/');
    if (slash == std::string::npos) return false;   // we expect a path like /home/x/vault
    std::string dir = path.substr(0, slash);
    if (mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) return false;

    //0600: owner read/write only
    std::string tmp = path + ".tmp";
    unlink(tmp.c_str());   // remove a leftover from an earlier crash
    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return false;

    FILE* f = fdopen(fd, "wb");   // wrap the descriptor so we can use fwrite
    if (f == nullptr) {
        close(fd);
        unlink(tmp.c_str());
        return false;
    }
    bool ok = fwrite(MAGIC, 1, sizeof MAGIC, f) == sizeof MAGIC
           && fwrite(salt.data(), 1, salt.size(), f) == salt.size()
           && fwrite(blob.data(), 1, blob.size(), f) == blob.size();
    if (fclose(f) != 0) ok = false;

    // 3. rename() replaces the old vault in one step: old file or new file, never half
    if (!ok || rename(tmp.c_str(), path.c_str()) != 0) {
        unlink(tmp.c_str());
        return false;
    }
    return true;
}

std::optional<VaultFile> read_vault(const std::string& path, size_t salt_len) {
    // O_NOFOLLOW: a symlink makes open() fail.
    int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return std::nullopt;

    // Check the file we actually opened (fstat on the descriptor, not on the name)
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return std::nullopt;
    }
    size_t size = static_cast<size_t>(st.st_size);
    if (size > MAX_FILE_SIZE || size < sizeof MAGIC + salt_len) {
        close(fd);
        return std::nullopt;
    }

    FILE* f = fdopen(fd, "rb");
    if (f == nullptr) {
        close(fd);
        return std::nullopt;
    }
    Bytes all(size);
    size_t got = fread(all.data(), 1, size, f);
    fclose(f);
    if (got != size) return std::nullopt;   // file ended early
    if (std::memcmp(all.data(), MAGIC, sizeof MAGIC) != 0) return std::nullopt;

    VaultFile vf;
    vf.salt.assign(all.begin() + sizeof MAGIC, all.begin() + sizeof MAGIC + salt_len);
    vf.blob.assign(all.begin() + sizeof MAGIC + salt_len, all.end());
    return vf;
}