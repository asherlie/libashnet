#!/bin/bash
ashnetd -ki 5 -ko 10 -u $(users) -i $(ip link | grep "state UP" | cut -d " " -f 2 | cut -d ":" -f 1)
