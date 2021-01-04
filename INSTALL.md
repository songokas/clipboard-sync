## Howto build

all instaliations packages end up in target/ directory

global deps:

* rust
* cargo
* cross
* docker

### debian based

deps:
* dpkg-sig

```
cargo install cargo-deb
make deb
```

### rpm based

deps:

* rpm
* ~/.rpmmacros

```
sudo rpm --import RPM-GPG-KEY-tomasj
cargo install cargo-rpm
make rpm
```

### arch based

deps:

* makepkg

```
cargo install cargo-pkgbuild
make pkg
```

### windows:

https://volks73.github.io/cargo-wix/cargo_wix/index.html

deps:

* windows
* visual studio 2019
* open visual studio install: c++ build tools, windows sdk, cli tools
* open x64 cmd for visual studio

```
cargo install cargo-wix
make msi
```

### android

```
make android
```
