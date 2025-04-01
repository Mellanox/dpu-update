#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024, Nvidia Inc. All rights reserved.


BASE_DIR=`dirname $0`
PY_SCRIPT=$BASE_DIR/OobUpdate.py

function check_and_set_env()
{
    check_tools

    # Check and install python requests module
    python3 -m pip show requests > /dev/null 2>&1
    if [ $? != 0 ];then
        # Try install requests module online firstly
        sudo python3 -m pip install requests
        if [ $? != 0 ];then
            sudo python3 -m pip install --no-index --find-links=$BASE_DIR/packages requests
        fi
    fi
}

function check_tools()
{
    commands[0]='python3             --version'
    commands[1]='curl                --version'
    commands[2]='strings             --version'
    commands[3]='grep                --version'
    commands[4]='ssh-keyscan         127.0.0.1'

    miss_tools=""
    for command in "${commands[@]}"; do
        eval "$command > /dev/null 2>&1"
        if [ $? != 0 ];then
            miss_tools="$miss_tools ${command:0:20}"
        fi
    done

    if [ -n "$miss_tools" ];then
        echo "Tools are needed to run this script:" $miss_tools
        exit 1
    fi
}

check_and_set_env

python3 $PY_SCRIPT "$@"