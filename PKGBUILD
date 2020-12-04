# Maintainer: Tomas Jakstas <tom.jakstas@gmail.com>
pkgname=clipboard-sync-bin
pkgver=0.1.0
pkgrel=1
pkgdesc="Secure clipboard sync across your devices"
url="https://github.com/songokas/clipboard-sync"
license=("LICENSE")
arch=("x86_64")
provides=("clipboard-sync")
options=("strip")
source=("https://github.com/songokas/clipboard-sync/releases/download/v$pkgver/clipboard-sync-$pkgver-x86_64.tar.gz")
sha256sums=("431f80f425367a479fc2d982ca07fee4586e185d5e22d87737cccaad4ce11b23")

package() {
    install -Dm755 clipboard-sync -t "$pkgdir/usr/bin/"
}
