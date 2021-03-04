#!/bin/sh

. ./config

curl -X POST http://$SERVER_IP:$SERVER_PORT/v2.1/vnf/instances/$VNFI_ID/servers/$VNFCI_ID/action -v | json_pp

