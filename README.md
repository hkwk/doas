# doas

A Rust implementation of `doas`, an alternative to `sudo` for running commands as other users.

## Features

- Simple configuration file syntax
- Supports permit/deny rules with options like nopass, keepenv
- PAM authentication
- Unix-like systems only

## Installation

1. Build the project:
   ```sh
   cargo build --release
   ```

2. Install the binary:
   ```sh
   sudo cp target/release/doas /usr/local/bin/
   sudo chown root:root /usr/local/bin/doas
   sudo chmod 4755 /usr/local/bin/doas
   ```

3. Create config file:
   ```sh
   sudo mkdir -p /usr/local/etc
   sudo cp doas.conf.sample /usr/local/etc/doas.conf
   sudo chown root:root /usr/local/etc/doas.conf
   sudo chmod 600 /usr/local/etc/doas.conf
   ```

4. Edit the config file to add rules, e.g.:
   ```
   permit yourusername as root
   ```

## Usage

```sh
doas command [args...]
doas -u user command [args...]
```

## Configuration

The config file is located at `/etc/doas.conf` or `/usr/local/etc/doas.conf`.

Syntax:
```
permit [nopass] [keepenv] [nolog] identity as target
```

- `permit` or `deny`
- `nopass`: no password required
- `keepenv`: keep environment variables
- `nolog`: don't log
- `identity`: the user who can run
- `target`: the user to run as

## Security

The binary must be setuid root to function properly. Ensure the config file is only readable by root.