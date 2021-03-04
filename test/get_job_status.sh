#!/bin/sh

. ./config

curl -X GET http://$SERVER_IP:$SERVER_PORT/v2/jobs/$JOB_ID -v | json_pp

