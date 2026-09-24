# passwordmanager

The passwordmanager will be a terminal application. The commands will be add to add a password name and password, list to get the list of the names of the passwords, delete to delete a password and its name and get to get a password corresponding to its name.

## Usage

The program is started once and prompts for the master password a single time. The master password is used to derive the encryption key and decrypt the vault. You are then dropped into an interactive prompt where you can run commands repeatedly without re-entering the master password, until you exit.

```
$ ./pwmanager
Master password: ********
pwmanager> add mail
Password: ********
Added.
pwmanager> get mail
Got.
pwmanager> list
mail
pwmanager> delete mail
Deleted.
pwmanager> exit
```

## Commands

| Command | Description |
|---|---|
| `add <name>` | Adds a new entry. Prompts interactively for the password to store (never passed as an argument, to avoid it ending up in shell/terminal history) |
| `get <name>` | Retrieves and displays the stored password for the given name |
| `list` | Lists the names of all stored entries (not the passwords themselves) |
| `delete <name>` | Deletes the entry for the given name. |
| `exit` | Wipes the derived key and any decrypted data from memory and closes the program. |


## Build and Run

Requirements: a C++ compiler with CMake, and [libsodium](https://libsodium.gitbook.io/doc/) installed.

```bash
cmake -B build
cmake --build build
./build/pwmanager
```