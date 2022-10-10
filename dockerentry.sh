#!/bin/bash

sh -c rc-status
rc-service sshd start
screen -dmS python3 /fullnet-core/core-server.py -c /fullnet-core/core-server.json
/usr/lib/frr/docker-start
