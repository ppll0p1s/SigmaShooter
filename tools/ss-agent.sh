#!/bin/bash

echo "Checking connectivity..."
check=$(curl -k "https://192.168.37.129:8443/api/checkConn")

if [[ $check == *"\"conn\":\"OK\""* ]]; then
    echo "Connectivity OK, running Sigma rules on SIEM"
    curl -k "https://192.168.37.129:8443/api/runAllRules/1"
fi
