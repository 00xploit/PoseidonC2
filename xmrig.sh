#!/bin/bash

# Empêcher les erreurs
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf > /dev/null

# Vérifier si les dépendances sont installées
if ! command -v git || ! command -v build-essential || ! command -v cmake || ! command -v automake || ! command -v libtool || ! command -v autoconf; then
  sudo apt-get install git build-essential cmake automake libtool autoconf -y
fi

# Télécharger xmrig si ce n'est pas déjà fait
if [ ! -d xmrig ]; then
  git clone https://github.com/xmrig/xmrig.git
fi

# Construire xmrig
cd xmrig/scripts
./build_deps.sh
cd ..
mkdir -p build
cd build
cmake .. -DXMRIG_DEPS=scripts/deps
make -j$(nproc)

# Exécuter xmrig en arrière-plan dans un screen
screen -dmS xmrig-screen ./xmrig -o xmr.2miners.com:2222 -u 45Jq4Gokx5BbwLnrLRUFquG4uSZ4mkcHDMYjibNBgrD291wG4Pz8bcx9KScWycUjW9iiejGY5PoQ9eMUsZaZ7Z6S1XggBKi 
