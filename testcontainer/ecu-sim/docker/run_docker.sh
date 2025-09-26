#!/bin/sh -e
docker run --privileged --cap-add NET_ADMIN -e USE_MULTIPLE_IPS=true -p 13400:13400 -p 8181:8181 -it ecu-sim
