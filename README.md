## Clipboard sync

synchronize your clipboard across multiple devices

simply copy in one device and paste in another device

file copying is supported as well (linux,windows,android only)

## Install

### Deb

```
wget https://github.com/songokas/clipboard-sync/releases/download/3.0.0/clipboard-sync_3.0.0-1_amd64.deb && sudo apt install ./clipboard-sync_3.0.0-1_amd64.deb
```

### RRM

```
sudo rpm --import https://raw.githubusercontent.com/songokas/clipboard-sync/3.0.0/.rpm/RPM-GPG-KEY-tomasj \
  && sudo yum install https://github.com/songokas/clipboard-sync/releases/download/3.0.0/clipboard-sync-3.0.0-1.x86_64.rpm
```

### Arch

```
sudo pacman-key --keyserver keyserver.ubuntu.com --recv-keys 175129AEEC57B0EB \
  && sudo pacman-key --lsign-key 175129AEEC57B0EB \
  && wget -q https://github.com/songokas/clipboard-sync/releases/download/3.0.0/clipboard-sync-3.0.0-1-x86_64.pkg.tar.zst.sig \
  && wget -q https://github.com/songokas/clipboard-sync/releases/download/3.0.0/clipboard-sync-3.0.0-1-x86_64.pkg.tar.zst \
  && sudo pacman -U clipboard-sync-3.0.0-1-x86_64.pkg.tar.zst
```

### Android

[download](https://github.com/songokas/clipboard-sync/releases/download/3.0.0/clipboard-sync-android_3.0.0.apk)

### Windows

[download](https://github.com/songokas/clipboard-sync/releases/download/3.0.0/clipboard-sync.exe)

### Others

[other versions](https://github.com/songokas/clipboard-sync/releases/tag/3.0.0)

### Install from source

install dependencies

```
sudo apt install libxcb1-dev libxcb-shape0-dev libxcb-render0-dev libxcb-xfixes0-dev
```

```
cargo install --git=https://github.com/songokas/clipboard-sync
```

no xserver, no dependencies above, only file support

```
cargo install --no-default-features --git=https://github.com/songokas/clipboard-sync
```

## Howto run

run with config (check example config below)

```
clipboard-sync --config ~/.config/clipboard-sync.yaml
```

run with default config:

```
# group name and key must be the same across your devices (check ~/.config/clipboard-sync/config.yml)
clipboard-sync
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
clipboard-sync --send-once
```

receive and quit

```
clipboard-sync --receive-once
```

exchange certificates with basic protocol (key must be defined)

```
# client1
clipboard-sync --send-public-key
# client2
clipboard-sync --receive-public-key
```

exchange certificates with quic protocol

```
# client1
clipboard-sync --protocol quic --send-public-key --danger-server-no-verify
# client2
clipboard-sync --protocol quic --receive-public-key --danger-client-no-verify
```

check for more options

```
clipboard-sync --help
```

use ipv6 with multicast

```
clipboard-sync  --bind-address "[::]:8900" --allowed-host "[ff02::123%3]:8900"
```

run as a user service

```
systemctl status --user clipboard-sync
```

## Examples

### sync clipboard across your devices on a local network

on every device run

```
clipboard-sync --key 11111111111111111111111111111111 --allowed-host 224.0.2.89:8900
```

### sync clipboard across your devices on a local network with specific host only

client 1 192.168.0.100

```
clipboard-sync --key 11111111111111111111111111111111 --allowed-host 192.168.0.200:8900
```

client 2 192.168.0.200

```
clipboard-sync --key 11111111111111111111111111111111 --allowed-host 192.168.0.100:8900
```

### sync clipboard across your devices on the external network (only certain nat types are supported or forward ports on your router

client 1 public ip client1-device-ip

```
clipboard-sync --key 11111111111111111111111111111111 --allowed-host client2-device-ip:8900 --send-using-address 0.0.0.0:8900 --heartbeat 20
```

client 2 public ip client2-device-ip

```
clipboard-sync --key 11111111111111111111111111111111 --allowed-host client1-device-ip:8900 --send-using-address 0.0.0.0:8900 --heartbeat 20
```

### sync clipboard across your devices on the external network (at least one device must be on a supported nat or with ports forwarded)

client 1 public ip client1-device-ip with forwarded 8900 port

```
clipboard-sync --key 11111111111111111111111111111111 --allowed-host client2-device-ip:8900:latest --send-using-address 0.0.0.0:8900 --heartbeat 20
```

client 2 public ip client2-device-ip behing symetric nat

```
clipboard-sync --key 11111111111111111111111111111111 --allowed-host client1-device-ip:8900 --send-using-address 0.0.0.0:8900 --heartbeat 20
```

### sync clipboard across your devices on the external network without forwarding ports or having a friendly nat

on a device that will be a relay server

server public ip clipsync.net with forwarded 8900 port

```
clipboard-relay --private-key 11111111111111111111111111111111 --protocol basic --bind-address 0.0.0.0:8900 --protocol tcp --bind-address 0.0.0.0:8901
```

on every device run

```
clipboard-sync --key 11111111111111111111111111111111 --allowed-host clipsync.net:8900 --send-using-address 0.0.0.0:8900 --heartbeat 20 --relay-host clipsync.net:8900 --relay-public-key "xskF0Ihe1s9gjIjw4VvL86FN8YkA3UHMjBzajRspwns="
```

warning: your clipboards goes through an external server and while the data is encrypted, there is a third party involved (unless you're running clipboard-relay yourself)

### sync clipboard to a file without affecting the main clipboard

```
clipboard-sync --key 11111111111111111111111111111111 --clipboard /home/user/any-file
```

read the clipboard later

```
xclip /home/user/any-file
```

send the clipboard

```
echo "clipboard contents" > /home/user/any-file
```

### sync clipboard with manual input

```
echo "clipboard contents" | clipboard-sync --key 11111111111111111111111111111111 --clipboard /dev/stdin --send-once
```

## overly complex example config demonstrating available options

```yaml
bind_addresses:
  # protocol: local socket address
  basic:
    - "0.0.0.0:8900"
    - "[::]:8900"
  tcp: "0.0.0.0:8903"
  tcp-tls: "0.0.0.0:8904"
  quic: "0.0.0.0:8904"

# optional unless using quic
certificates:
  private_key: tests/cert.key
  certificate_chain: tests/cert.crt
  remote_certificates: tests/cert-verify

# send_using_address and visible_ip are per group as well
send_using_address: "0.0.0.0:8901"

# if behind nat/incorrect ip is used
visible_ip: "my-public-ip"

# max bytes to receive per connection
max_receive_buffer: 10485760
# max bytes per file when sending/receiving files
max_file_size: 1048576

# whether to send initial clipboard when application starts
send_clipboard_on_startup: false

# if receiving once how many seconds to wait before quitting
receive_once_wait: 20

groups:
  specific_hosts:
    key: "32323232323232323232323232323232"
    allowed_hosts:
      - "192.168.0.153:8900"
      - "192.168.0.54:20034"
    clipboard: clipboard # can be clipboard, /path/to/file , /path/to/directory/
  local_network: # allowed_hosts default to local network multicast
    key: "32323232323232323232323232323232"
  nat_traversal_client1:
    key: "32323232323232323232323232323232"
    visible_ip: "2.2.2.2" # if not provided defaults to public ip when sending to external networks
    send_using_address:
      - "0.0.0.0:8900"
      - "[::]:8900"
    heartbeat: 20 # send dummy packet every 20 seconds
    allowed_hosts:
      - "external.net:8900"
  nat_traversal_client2: # on the other host
    key: "32323232323232323232323232323232"
    visible_ip: "external.net"
    send_using_address: "0.0.0.0:8900"
    heartbeat: 20
    allowed_hosts:
      - "2.2.2.2:8900"
  client1_to_relay: # group name should be the same on every device
    key: "32323232323232323232323232323232"
    send_using_address: "0.0.0.0:8900"
    heartbeat: 20
    allowed_hosts:
      - "relay.net:8900"
  client2_to_relay: # group name should be the same on every device
    key: "32323232323232323232323232323232"
    send_using_address: "0.0.0.0:8900"
    heartbeat: 20
    allowed_hosts:
      - "relay.net:8900"
  static_relay: # group name should be the same on every device
    key: "32323232323232323232323232323232"
    send_using_address: "0.0.0.0:8900"
    heartbeat: 20
    allowed_hosts:
      - "client1_ip:8900:latest" # latest - client source port from the latest received message or 8900
      - "client2_ip:8900:latest"
  dynamic_relay:
    key: "32323232323232323232323232323232"
    send_using_address: "0.0.0.0:8900"
    heartbeat: 20
    allowed_hosts:
      - "relay.net:8900"
    relay:
      host: "relay.net:8900" # relay clipboards through this server
      public_key: "some key"

  local_network_file:
    key: "32323232323232323232323232323232"
    clipboard: /tmp/cliboard # sync file
  local_network_dir:
    key: "32323232323232323232323232323232"
    clipboard: /tmp/clipboard/dir/ # sync dir
  receive_only_dir:
    key: "32323232323232323232323232323232"
    clipboard: /tmp/clipboard/dir/ # files will be created as /tmp/clipboard/dir/192.168.0.111
    allowed_hosts:
      - "192.168.0.111:0" # port 0 - receive only
      - "192.168.0.112:0"
    protocol: basic
```

use only what you need. its usually enough to have a simple configuration such as:

```yaml
# file: ~/.config/clipboard-sync/config.yml
groups:
  default:
    key: your_key_that_is_32_chars_long32
```

and run

```
clipboard-sync
```

### relay systemd service

```
[Unit]
Description=Clipboard relay service

[Service]
# as root`
# `adduser --system --home /etc/clipboard-relay --group cliprel`
# `openssl rand -out /etc/clipboard-relay/key 32 && chown cliprel /etc/clipboard-relay/key && chmod 600 /etc/clipboard-relay/key`
# with 32 bytes content
# or
# `systemctl edit clipboard-relay`
# and override what you see fit
ExecStart=/usr/bin/clipboard-relay --private-key /etc/clipboard-relay/key --protocol basic --protocol laminar --protocol tcp
NoNewPrivileges=true
User=cliprel
Group=cliprel
Restart=on-failure

[Install]
WantedBy=multi-user.targett
```

## TODO

- test on iOS
