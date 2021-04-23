#!/bin/bash
set -eu

SHELLPATH=`dirname $0`
SHELLPATH=$(cd $SHELLPATH; pwd)
MODNAME="tcpprobe_plus"

USAGE="$0 LISTEN_PORT"
if (($# < 1)); then
    echo $USAGE
    exit 1
fi

portnum="$1"

(cd $SHELLPATH; make)

if [ -n "$(lsmod | grep $MODNAME)" ]; then
    sudo rmmod $MODNAME
fi
sudo insmod $SHELLPATH/${MODNAME}.ko port=$portnum
