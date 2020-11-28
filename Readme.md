## Clipboard sync

synchronize your clipboards across multiple devices

## run without config 

```
clipboard-sync --allowed-host 192.168.0.1:83332 --group test  --key $(< "key")
```

## run with config 

```
clipboard-sync --config ~/.config/clipboard-sync.yaml
```

### example config

```yaml
bind_address: "0.0.0.0:8900"
# send_address and public_ip are per group as well
send_using_address: "0.0.0.0:8901"
public_ip: "8.2.23.2"

groups:
  specific_hosts:
    key: "32323232323232323232323232323232"
    allowed_hosts:
      - "192.168.0.153" # port defaults to bind_address port
      - "192.168.0.54:20034"
      - "8.3.2.3:9000"
  local_network: 
    key: "32323232323232323232323232323232"
    # allowed_hosts default to local network multicast
```

