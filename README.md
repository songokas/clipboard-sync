## Clipboard sync

synchronize your clipboard across multiple devices

encrypted udp

simply copy in one device and paste in another device

file copying is supported as well (linux only)

## Install

### Deb

```
wget https://github.com/songokas/clipboard-sync/releases/download/1.0.0/clipboard-sync_1.0.0_amd64.deb && sudo apt install ./clipboard-sync_1.0.0_amd64.deb
```
### RRM

```
sudo rpm --import https://raw.githubusercontent.com/songokas/clipboard-sync/1.0.0/.rpm/RPM-GPG-KEY-tomasj \
  && sudo yum install https://github.com/songokas/clipboard-sync/releases/download/1.0.0/clipboard-sync-1.0.0-1.x86_64.rpm
```

### Arch

```
sudo pacman-key --keyserver keyserver.ubuntu.com --recv-keys 175129AEEC57B0EB \
  && sudo pacman-key --lsign-key 175129AEEC57B0EB \
  && wget -q https://github.com/songokas/clipboard-sync/releases/download/1.0.0/clipboard-sync-1.0.0-1-x86_64.pkg.tar.zst.sig \
  && wget -q https://github.com/songokas/clipboard-sync/releases/download/1.0.0/clipboard-sync-1.0.0-1-x86_64.pkg.tar.zst \
  && sudo pacman -U clipboard-sync-1.0.0-1-x86_64.pkg.tar.zst
```

### Android

[download](https://github.com/songokas/clipboard-sync/releases/download/1.0.0/clipboard-sync-android_1.0.0.apk)

### Windows

[download](https://github.com/songokas/clipboard-sync/releases/download/1.0.0/clipboard-sync-1.0.0-x86_64.msi)


### Others

[other versions](https://github.com/songokas/clipboard-sync/releases/tag/1.0.0)

### Install from source

```
cargo install --root="~/bin/" --git=https://github.com/songokas/clipboard-sync
```

## Howto run

run with default config:

group name and key must be the same across your devices

```
clipboard-sync --autogenerate
```

run with key:

```
clipboard-sync --key 32323232323232323232323232323232
```

run with multiple options:

```
KEY="32323232323232323232323232323232"
clipboard-sync --key <(echo "$KEY") --allowed-host "127.0.0.1:8000" --clipboard /tmp/b --verbosity debug --bind-address 127.0.0.1:9000 --send-using-address 127.0.0.1:9001
```

send and quit

```
clipboard-sync --autogenerate --send-once
```

receive and quit

```
clipboard-sync --config ~/.config/clipboard-sync/config.yml --receive-once
```

check for more options 

```
clipboard-sync --help
```

## run with config 

```
clipboard-sync --config ~/.config/clipboard-sync.yaml
```

### example config

```yaml
bind_addresses:
  # protocol: local socket address
  basic: "0.0.0.0:8900"
  frames: "0.0.0.0:8901"

# optional unless using quic
certificates:
  private_key: tests/cert.key
  public_key: tests/cert.crt
  verify_dir: tests/cert-verify

# send_using_address and visible_ip are per group as well
send_using_address: "0.0.0.0:8901"

visible_ip: "my-public-ip"

# max bytes to receive per connection
max_receive_buffer: 10485760

# whether to send initial clipboard when application starts
send_clipboard_on_startup: false

# if receiving once how many seconds to wait
receive_once_wait: 20

groups:
  specific_hosts:
    key: "32323232323232323232323232323232"
    allowed_hosts:
      - "192.168.0.153:8900"
      - "192.168.0.54:20034"
    clipboard: clipboard # can be clipboard, /path/to/file , /path/to/directory/
  local_network: 
    key: "32323232323232323232323232323232"
    # allowed_hosts default to local network multicast
  external:
    key: "32323232323232323232323232323232"
    visible_ip: "2.2.2.2"
    send_using_address: "0.0.0.0:9000"
    allowed_hosts:
      - "external.net:80"
  local_network_file: 
    key: "32323232323232323232323232323232"
    clipboard: /tmp/cliboard # sync file
  local_network_dir:
    key: "32323232323232323232323232323232"
    clipboard: /tmp/cliboard/dir/ # sync dir
  receive_only_dir:
    key: "32323232323232323232323232323232"
    clipboard: /tmp/cliboard/dir/ # files will be created as /tmp/cliboard/dir/192.168.0.111
    allowed_hosts:
      - "192.168.0.111:0" # port 0 - receive only
      - "192.168.0.112:0"
    protocol: frames
```







