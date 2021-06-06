$arch = <<-SCRIPT
sudo pacman -S --noconfirm fakeroot
sudo pacman-key --keyserver keyserver.ubuntu.com --recv-keys 175129AEEC57B0EB \
  && sudo pacman-key --lsign-key 175129AEEC57B0EB \
  && wget -q https://github.com/songokas/clipboard-sync/releases/download/2.0.1/clipboard-sync-2.0.1-1-x86_64.pkg.tar.zst.sig \
  && wget -q https://github.com/songokas/clipboard-sync/releases/download/2.0.1/clipboard-sync-2.0.1-1-x86_64.pkg.tar.zst \
  && sudo pacman -U clipboard-sync-2.0.1-1-x86_64.pkg.tar.zst
clipboard-sync --autogenerate
SCRIPT

$rpm = <<-SCRIPT
sudo rpm --import https://raw.githubusercontent.com/songokas/clipboard-sync/2.0.1/.rpm/RPM-GPG-KEY-tomasj \
  && sudo yum localinstall https://github.com/songokas/clipboard-sync/releases/download/2.0.1/clipboard-sync-2.0.1-1.x86_64.rpm
clipboard-sync --autogenerate
SCRIPT

$deb = <<-SCRIPT
wget https://github.com/songokas/clipboard-sync/releases/download/2.0.1/clipboard-sync_2.0.1_amd64.deb && sudo apt --assume-yes install ./clipboard-sync_2.0.1_amd64.deb
clipboard-sync --autogenerate
SCRIPT

Vagrant.configure("2") do |config|

  config.vm.synced_folder "./", "/vagrant", type: "rsync", rsync__exclude: ['target/']

  config.vm.define "ubuntu2004" do |ubuntu|
    ubuntu.vm.box = "generic/ubuntu2004"
    ubuntu.vm.provision "shell", inline: $deb
  end

  config.vm.define "fedora33" do |fedora|
    fedora.vm.box = "generic/fedora33"
    fedora.vm.provision "shell", inline: $rpm
  end

  config.vm.define "arch" do |arch|
    arch.vm.synced_folder "~/.gnupg", "/home/vagrant/.gnupg", type: "rsync"
    arch.vm.box = "generic/arch"
    arch.vm.provision "shell", inline: $arch
  end
end