#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024, Nvidia Inc. All rights reserved.


BASE_DIR=`dirname $0`
PY_SCRIPT=$BASE_DIR/OobUpdate.py

function check_and_set_env()
{
    python3 --version > /dev/null 2>&1
    if [ $? != 0 ];then
        echo "python3 is needed to rerun this script"
        exit 1
    fi

    # Use local openssl lib, if version < 3.6
    second_ver=`python3 --version |cut -d. -f2`
    if [ "$second_ver" -lt 6 ];then
        ABS_PATH=`realpath $BASE_DIR`
        export LD_LIBRARY_PATH=$ABS_PATH/lib/openssl-1.1.1:$LD_LIBRARY_PATH
    fi

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

check_and_set_env

python3 $PY_SCRIPT $@