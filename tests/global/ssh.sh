#!/bin/bash

ssh root@server ls > /dev/null
exit $?
