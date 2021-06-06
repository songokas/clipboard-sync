## Clipboard sync

synchronize your clipboard across multiple devices

encrypted udp

simply copy in one device and paste in another device

file copying is supported as well (linux only)

## Install

### Deb

```
wget https://github.com/songokas/clipboard-sync/releases/download/2.0.1/clipboard-sync_2.0.1_amd64.deb && sudo apt install ./clipboard-sync_2.0.1_amd64.deb
```
### RRM

```
sudo rpm --import https://raw.githubusercontent.com/songokas/clipboard-sync/2.0.1/.rpm/RPM-GPG-KEY-tomasj \
  && sudo yum install https://github.com/songokas/clipboard-sync/releases/download/2.0.1/clipboard-sync-2.0.1-1.x86_64.rpm
```

### Arch

```
sudo pacman-key --keyserver keyserver.ubuntu.com --recv-keys 175129AEEC57B0EB \
  && sudo pacman-key --lsign-key 175129AEEC57B0EB \
  && wget -q https://github.com/songokas/clipboard-sync/releases/download/2.0.1/clipboard-sync-2.0.1-1-x86_64.pkg.tar.zst.sig \
  && wget -q https://github.com/songokas/clipboard-sync/releases/download/2.0.1/clipboard-sync-2.0.1-1-x86_64.pkg.tar.zst \
  && sudo pacman -U clipboard-sync-2.0.1-1-x86_64.pkg.tar.zst
```

### Android

[download](https://github.com/songokas/clipboard-sync/releases/download/2.0.1/clipboard-sync-android_2.0.1.apk)

### Windows

[download](https://github.com/songokas/clipboard-sync/releases/download/2.0.1/clipboard-sync-2.0.1-x86_64.msi)


### Others

[other versions](https://github.com/songokas/clipboard-sync/releases/tag/2.0.1)

### Install from source

```
cargo install --root="~/bin/" --git=https://github.com/songokas/clipboard-sync
```

## Howto run

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

check for more options 

```
clipboard-sync --help
```

run with config 

```
clipboard-sync --config ~/.config/clipboard-sync.yaml
```

use ipv6 with multicast

```
clipboard-sync  --bind-address "[::]:8900" --allowed-host "[ff02::123%3]:8900"
```

### example config

```yaml
bind_addresses:
  # protocol: local socket address
  basic: 
    - "0.0.0.0:8900"
    - "[::]:8900"
  frames: "0.0.0.0:8901"
  laminar: "0.0.0.0:8902"
  tcp: "0.0.0.0:8903" 
  #quic: "0.0.0.0:8904"

# optional unless using quic
certificates:
  private_key: tests/cert.key
  public_key: tests/cert.crt
  verify_dir: tests/cert-verify

# send_using_address and visible_ip are per group as well
send_using_address: "0.0.0.0:8901"

# if behind nat/incorrect ip is used
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
  local_network:  # allowed_hosts default to local network multicast
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


### TODO

* finalize quic
* test on iOS
* clipboard use events instead of reading in interval
* file copy between platforms
* improve docs / add more examples