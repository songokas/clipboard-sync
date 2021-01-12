
ANDROID_APP ?= $(HOME)/AndroidStudioProjects/clipboard-sync-android/
HEADLESS_OPTIONS = --release --no-default-features --features frames
DEB_OPTIONS = --no-build
ARCHS=i686-unknown-linux-gnu x86_64-unknown-linux-gnu armv7-unknown-linux-gnueabihf aarch64-unknown-linux-gnu
ANDROID_ARCHS=x86_64-linux-android i686-linux-android arm-linux-androideabi aarch64-linux-android 
USER_ID ?= $(shell id -u)
GROUP_ID ?= $(shell id -g)
LIB_NAME = libclipboard_sync.so
CERT_PATH ?= $(HOME)/.ssh/app-sign-cert.pem
KEY_PATH ?= $(HOME)/.ssh/app-sign-key.pem
VERSION = 0.1.0

define docker_build
	docker run \
		--rm \
		--env CARGO_HOME=$(PWD)/target/cache \
		--user $(USER_ID):$(GROUP_ID) \
		--volume $(PWD):$(PWD) \
		--workdir $(PWD) \
		$(1) \
		$(2)
endef

all: docker build deb rpm pkg windows android

build:
	$(call docker_build, clipboard-sync/x86_64, cargo build --target x86_64-unknown-linux-gnu $(HEADLESS_OPTIONS))
	@mv target/x86_64-unknown-linux-gnu/release/clipboard-sync target/x86_64-unknown-linux-gnu/release/clipboard-sync-headless

	$(call docker_build, clipboard-sync/x86_64, cargo build --target x86_64-unknown-linux-gnu --release)
	$(call docker_build, clipboard-sync/x86_64, cargo build --target i686-unknown-linux-gnu --release)
	$(call docker_build, clipboard-sync/arm, cargo build --target aarch64-unknown-linux-gnu --release)
	# $(call docker_build, clipboard-sync/arm, cargo build --target arm-unknown-linux-gnueabihf $(HEADLESS_OPTIONS))
	$(call docker_build, clipboard-sync/arm, cargo build --target armv7-unknown-linux-gnueabihf $(HEADLESS_OPTIONS))

strip:
	$(foreach arch, $(ARCHS), cargo strip --target $(arch);)

docker:
	docker build -t clipboard-sync/x86_64 -f docker/x86_64 docker/
	docker build -t clipboard-sync/arm -f docker/arm docker/

deb: build
	@$(call docker_build, clipboard-sync/x86_64, cargo deb --target x86_64-unknown-linux-gnu $(DEB_OPTIONS))
	@$(call docker_build, clipboard-sync/x86_64, cargo deb --target i686-unknown-linux-gnu $(DEB_OPTIONS))
	@$(call docker_build, clipboard-sync/arm, cargo deb --target aarch64-unknown-linux-gnu $(DEB_OPTIONS) --variant aarch64)
	# @$(call docker_build, clipboard-sync/arm, cargo deb --target arm-unknown-linux-gnueabihf $(DEB_OPTIONS) --variant headless)
	# @dpkg-sig -s builder target/arm-unknown-linux-gnueabihf/debian/clipboard-sync-headless_$(VERSION)_armhf.deb
	@$(call docker_build, clipboard-sync/arm, cargo deb --target armv7-unknown-linux-gnueabihf $(DEB_OPTIONS) --variant headless)


rpm: build
	@$(call docker_build, clipboard-sync/x86_64, cargo rpm build --target x86_64-unknown-linux-gnu)
	@$(call docker_build, clipboard-sync/x86_64, cargo rpm build --target i686-unknown-linux-gnu)

pkg:
	@mkdir -p target/pkgbuild
	@cp arch/PKGBUILD target/pkgbuild
	cd target/pkgbuild && makepkg -s --force --sign

# pkg-in-vagrant:
# 	vagrant up arch
# 	vagrant ssh arch
# 	vagrant scp arch:/vagrant/target/pkgbuild/clipboard-sync-*.pkg.tar* dist/

windows:
	cross build --target x86_64-pc-windows-gnu --release
	# @TODO more undefined references to `_Unwind_Resume' follow
	# cross build --target i686-pc-windows-gnu --release

# runs on widows only
msi:
	cargo wix
	cargo wix sign

android:
	$(foreach arch, $(ANDROID_ARCHS), cross build --target $(arch) $(HEADLESS_OPTIONS);)

android-copy: android
	@cp target/i686-linux-android/release/libclipboard_sync.so $(ANDROID_APP)/app/src/main/jniLibs/x86/libclipboard_sync.so
	@cp target/x86_64-linux-android/release/libclipboard_sync.so $(ANDROID_APP)/app/src/main/jniLibs/x86_64/libclipboard_sync.so
	@cp target/aarch64-linux-android/release/libclipboard_sync.so $(ANDROID_APP)/app/src/main/jniLibs/arm64-v8a/libclipboard_sync.so
	@cp target/arm-linux-androideabi/release/libclipboard_sync.so $(ANDROID_APP)/app/src/main/jniLibs/armeabi-v7a/libclipboard_sync.so

clean:
	cargo clean

test:
	cargo test
	cargo test --features quic

sign: sign-windows
	@rpm --addsign target/x86_64-unknown-linux-gnu/release/rpmbuild/RPMS/x86_64/clipboard-sync-$(VERSION)-1.x86_64.rpm
	@rpm --addsign target/i686-unknown-linux-gnu/release/rpmbuild/RPMS/i686/clipboard-sync-$(VERSION)-1.i686.rpm

	@dpkg-sig -s builder target/x86_64-unknown-linux-gnu/debian/clipboard-sync_$(VERSION)_amd64.deb
	@dpkg-sig -s builder target/i686-unknown-linux-gnu/debian/clipboard-sync_$(VERSION)_i386.deb
	@dpkg-sig -s builder target/aarch64-unknown-linux-gnu/debian/clipboard-sync-aarch64_$(VERSION)_arm64.deb
	@dpkg-sig -s builder target/armv7-unknown-linux-gnueabihf/debian/clipboard-sync-headless_$(VERSION)_armhf.deb

sign-windows:
	osslsigncode sign -certs $(CERT_PATH) -key $(KEY_PATH) \
		-in target/clipboard-sync-$(VERSION)-x86_64.msi \
		-out dist/clipboard-sync-$(VERSION)-x86_64.msi \
		-ts http://timestamp.digicert.com \
		-add-msi-dse


release: deb rpm strip sign
	mkdir -p dist
	cp target/*/debian/clipboard-sync* dist/
	cp target/x86_64-unknown-linux-gnu/release/rpmbuild/RPMS/x86_64/* dist/
	cp target/i686-unknown-linux-gnu/release/rpmbuild/RPMS/i686/* dist/
	cp target/x86_64-unknown-linux-gnu/release/clipboard-sync dist/clipboard-sync-amd64-binary
	cp target/i686-unknown-linux-gnu/release/clipboard-sync dist/clipboard-sync-i686-binary
	cp target/x86_64-unknown-linux-gnu/release/clipboard-sync-headless dist/clipboard-sync-amd64-headless-binary
	
.PHONY: clean android windows docker deb rpm pkg strip all release sign sign-windows
