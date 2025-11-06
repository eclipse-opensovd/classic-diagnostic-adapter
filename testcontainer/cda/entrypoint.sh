#!/bin/sh -e

DOIP_TESTER_IP=$(ip -4 a show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

echo "Using arguments: $@"
echo "Using DoIpTesterIp: $DOIP_TESTER_IP"

find "." -maxdepth 1 -type f -print0 | xargs -0 sha1sum

/app/opensovd-cda --tester-address "$DOIP_TESTER_IP" $@
