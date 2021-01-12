$archInstall = <<-SCRIPT
pacman -S --noconfirm fakeroot
# manually
# cd /vagrant && cp arch/makepkg.conf ~/.makepkg.conf && make pkg
# namcap target/pkgbuild/clipboard-sync*.pkg.tar.zst
# vagrant scp arch:/vagrant/target/pkgbuild/clipboard-sync-*.pkg.tar* dist/
SCRIPT


Vagrant.configure("2") do |config|

  config.vm.synced_folder "./", "/vagrant", type: "rsync", rsync__exclude: ['target/']

  config.vm.define "ubuntu2040" do |ubuntu|
    ubuntu.vm.box = "generic/ubuntu2040"
  end

  config.vm.define "fedora28" do |fedora|
    fedora.vm.box = "generic/fedora28"
  end

  config.vm.define "arch" do |arch|
    arch.vm.synced_folder "~/.gnupg", "/home/vagrant/.gnupg", type: "rsync"
    arch.vm.box = "generic/arch"
    arch.vm.provision "shell", inline: $archInstall
  end
end