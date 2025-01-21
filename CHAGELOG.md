## [Unreleased]

## [3.0.1] - 2025-01-04

## Added

- max connection limit
- ci tests

## Changed

- clipboard bump version

## Fixed

- macos support
- tcptls buffer flush

## [3.0.0] - 2025-01-04

## Added

- quic protocol
- tcp tls protocol
- additional configuration and cli arguments for certificates
- event handling for x11 clipboard
- wayland clipboard
- copy files on windows

## Changed

- message format for all protocols (breaking change)

## Removed

- frames protocol
- laminar protocol

### Fixed

- cli arguments max-file-size max-buffer-size names
- minor memory consumption reduction on send/received

## [2.1.1] - 2021-09-19

### Fixed

- cli arguments max-file-size max-buffer-size names
- minor memory consumption reduction on send/received

## [2.1.0] - 2021-06-13

### Added

- clipboard-relay to relay traffic, when direct connection is not possible
- android send/receive files

### Fixed

- file clipboard encode/decode
- basic protocol use tcp with multicast for first host

## [2.0.1] - 2021-06-06

### Fixed

- unable to bind and send using the same port

## [2.0.0] - 2021-05-31

### Added

- laminar protocol
- tcp protocol
- heartbeat configuration and cli argument
- retrieve public ip address feature
- file, directory notification changes
- ntp-server and message-valid-for cli and configuration

### Changed

- reuse receiver socket for sending
- cli and configuration bind_address, send_using_address can take multiple values
- use xchacha instead of chacha

## [1.1.0] - 2021-02-27

### Added

- linux handle different clipboards
- ipv6 multicast
- use bind address from cli as default
- default key from cli

### Fixed

- frames protocol

## [1.0.0] - 2021-02-01

### Added

- linux copy files
- visible ip added
- receive once timeout
- path synchronization
- message type to identify clipboard format added
- clipboard using targets

### Fixed

- multicast ignore loop
