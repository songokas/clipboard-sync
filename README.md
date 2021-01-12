## Clipboard sync

securely synchronize your clipboards across multiple devices

## Install

* debian[](download)
* rpm [](download)
* arch [](download)
* android [](dowload)
* windows [](download)

from source

```
cargo install --root="~/bin/" --git=https://github.com/songokas/clipboard-sync
```

## Howto run

run with default config:

```
clipboard-sync --autogenerate
```

run with key:

```
KEY="32323232323232323232323232323232"
clipboard-sync --key <(echo "$KEY")
```

run with multiple options:

```
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

# optional unless using quic
certificates:
  private_key: tests/cert.key
  public_key: tests/cert.crt
  verify_dir: tests/cert-verify

# send_using_address and public_ip are per group as well
send_using_address: "0.0.0.0:8901"

public_ip: "my-public-ip"

# max bytes to receive per connection
max_receive_buffer: 10485760

# whether to send initial clipboard when application starts
send_clipboard_on_startup: false

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
    public_ip: "2.2.2.2"
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
```







