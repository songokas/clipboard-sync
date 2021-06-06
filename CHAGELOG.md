## [Unreleased]
- quic quinn protocol implementation lacks client verification, version negotiation, retry token
- quic quiche protocol implementation lacks client verification, version negotiation, retry token

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

* linux handle different clipboards
* ipv6 multicast
* use bind address from cli as default
* default key from cli
### Fixed

* frames protocol

## [1.0.0] - 2021-02-01

### Added

* linux copy files
* visible ip added
* receive once timeout
* path synchronization
* message type to identify clipboard format added
* clipboard using targets
### Fixed

* multicast ignore loop