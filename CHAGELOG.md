## [Unreleased]
- quic quinn protocol implementation lacks client verification, version negotiation, retry token
- quic quiche protocol implementation lacks client verification, version negotiation, retry token
- 

## [1.2.0] - 2021-05-19

### Added
- laminar protocol
- tcp protocol
- heartbeat configuration and cli argument
- retrieve public ip address feature
- file, directory notification changes

### Changed
- reuse receiver socket for sending
- configuration bind_address, send_using_address can take multiple values
- cli arguments bind-address, send-using-address can take multiple values separated by comma

