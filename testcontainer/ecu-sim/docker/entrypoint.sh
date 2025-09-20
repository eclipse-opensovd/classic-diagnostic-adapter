#!/bin/bash -ex

# shellcheck disable=SC2145
ls -la /app

if [ "$USE_MULTIPLE_IPS" = "true" ]; then
  ./ipcli.sh add eth0 100 '{100..150}'
fi

export SIM_NETWORK_INTERFACE=${SIM_NETWORK_INTERFACE:-eth0}

java -Djava.net.preferIPv4Stack=true $JAVA_OPTS -jar "/app/ecu-sim-all.jar" "$@"
