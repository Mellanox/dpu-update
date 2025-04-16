#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024, NVIDIA CORPORATION. All rights reserved.

import argparse
import os
import sys
import random
import string
import shutil
import time
import re
import json
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '/src')
import bf_dpu_update


# Version of this script tool
Version = '25.04-1.5'


def get_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-U',             metavar="<username>",        dest="username",     type=str, required=False, help='Username of BMC')
    parser.add_argument('-P',             metavar="<password>",        dest="password",     type=str, required=False, help='Password of BMC')
    parser.add_argument('-S',             metavar="<ssh_username>",    dest="ssh_username",     type=str, required=False, help='Username of BMC SSH access')
    parser.add_argument('-K',             metavar="<ssh_password>",    dest="ssh_password",     type=str, required=False, help='SSH password of BMC')
    parser.add_argument('-F',             metavar="<firmware_file>",   dest="fw_file_path", type=str, required=False, help='Firmware file path (absolute/relative)')
    parser.add_argument('-T',             metavar="<module>",          dest="module",       type=str, required=False, help='The module to be updated: BMC|CEC|BIOS|FRU|CONFIG|BUNDLE', choices=('BMC', 'CEC', 'BIOS', 'FRU', 'CONFIG', 'BUNDLE'))
    parser.add_argument('-H',             metavar="<bmc_ip>",          dest="bmc_ip",       type=str, required=False, help='IP/Host of BMC')
    parser.add_argument('-C',             action='store_true',         dest="clear_config",           required=False, help='Reset to factory configuration (Only used for BMC|BIOS)')
    parser.add_argument('-o', '--output', metavar="<output_log_file>", dest="output_file",  type=str, required=False, help='Output log file')
    parser.add_argument('-p', '--port',   metavar="<bmc_port>",        dest="bmc_port",     type=str, required=False, help='Port of BMC (443 by default).')
    parser.add_argument('--bios_update_protocol', metavar='<bios_update_protocol>', dest="bios_update_protocol", required=False, help=argparse.SUPPRESS, choices=('HTTP', 'SCP'))
    parser.add_argument('--config',       metavar='<config_file>',     dest="config_file",  type=str, required=False, help='Configuration file')
    parser.add_argument('-s',             action='append',             metavar="<oem_fru>", dest="oem_fru",           type=str, required=False, help='FRU data in the format "Section:Key=Value"')
    parser.add_argument('-v', '--version',     action='store_true',    dest="show_version",           required=False, help='Show the version of this scripts')
    parser.add_argument('--skip_same_version', action='store_true',    dest="skip_same_version",      required=False, help='Do not upgrade, if upgrade version is the same as current running version')
    parser.add_argument('--show_all_versions', action='store_true',    dest="show_all_versions",      required=False, help=argparse.SUPPRESS)
    parser.add_argument('-d', '--debug',       action='store_true',    dest="debug",                  required=False, help='Show more debug info')
    parser.add_argument('-L', metavar="<path>", dest="config_path", type=str, required=False, help='Linux path to save the cfg file', default='/tmp')
    parser.add_argument('--task-id',    metavar="<task_id>",    dest="task_id",     type=str, required=False, help='Unique identifier for the task')
    return parser

def create_random_suffix():
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(5))

def create_cfg_file(username, password, ssh_username, ssh_password, config_path, task_id):
    # Create a separate temporary directory for each task
    task_dir = os.path.join(config_path, "task_{}".format(task_id))
    if not os.path.exists(task_dir):
        try:
            os.makedirs(task_dir)
        except OSError as e:
            print("Error creating directory {}: {}".format(task_dir, e))
            return None
    cfg_file_name = "{}_{}.cfg".format(task_id, create_random_suffix())
    cfg_file_path = os.path.join(task_dir, cfg_file_name)
    try:
        with open(cfg_file_path, 'w') as cfg_file:
            cfg_file.write('BMC_USER="{}"\n'.format(username))
            cfg_file.write('BMC_PASSWORD="{}"\n'.format(password))
            cfg_file.write('BMC_SSH_USER="{}"\n'.format(ssh_username))
            cfg_file.write('BMC_SSH_PASSWORD="{}"\n'.format(ssh_password))
            cfg_file.write('BMC_REBOOT="yes"\n')
        print("Configuration file saved to {}".format(cfg_file_path))
        return cfg_file_path
    except Exception as e:
        print("Error creating configuration file: {}".format(e))
        return None

def merge_files(cfg_file_path, fw_file_path, task_id):
    if not cfg_file_path or not fw_file_path or not fw_file_path.endswith('.bfb'):
        return fw_file_path
    config_dir = os.path.dirname(cfg_file_path)
    new_fw_name = "{}_{}_new.bfb".format(task_id, create_random_suffix())
    new_fw_path = os.path.join(config_dir, new_fw_name)
    try:
        with open(fw_file_path, 'rb') as f1, open(cfg_file_path, 'rb') as f2, open(new_fw_path, 'wb') as out:
            shutil.copyfileobj(f1, out)
            shutil.copyfileobj(f2, out)
        print("New merged file created at {}".format(new_fw_path))
        return new_fw_path
    except Exception as e:
        print("Error merging files: {}".format(e))
        return fw_file_path

def extract_info_json(file_path, start_pattern, end_pattern):
    # Open the binary file
    with open(file_path, 'rb') as f:
        binary_data = f.read()

    # Decode the binary data into a string (ignoring decoding errors)
    try:
        text_data = binary_data.decode('utf-8')
    except UnicodeDecodeError:
        text_data = binary_data.decode('utf-8', errors='ignore')

    # Find starting '{' before the start pattern
    start_idx = text_data.find(start_pattern)
    if start_idx == -1:
        return "Start pattern not found."

    # Find the first '{' before the start pattern
    open_brace_idx = text_data.rfind('{', 0, start_idx)
    if open_brace_idx == -1:
        return "No opening brace '{' found before start pattern."

    # Find end pattern and closing '}' after it
    end_idx = text_data.find(end_pattern, open_brace_idx)
    if end_idx == -1:
        return "End pattern not found."

    # Find the first '}' after the end pattern
    close_brace_idx = text_data.find('}', end_idx)
    if close_brace_idx == -1:
        return "No closing brace '}' found after end pattern."

    # Extract the JSON segment
    json_segment = text_data[open_brace_idx:close_brace_idx+1]

    return json_segment

def extract_info(new_fw_file_path, config_path, task_id):
    start_pattern = "This JSON represents"
    end_pattern = "Members@odata.count"
    info_json = extract_info_json(new_fw_file_path, start_pattern, end_pattern)
    info_dir = os.path.join(config_path, "task_{}".format(task_id))
    info_file_name = "{}_info.json".format(task_id)
    info_file_path = os.path.join(info_dir, info_file_name)
    try:
        with open(info_file_path, 'w') as info_file:
            info_file.write(info_json)
    except Exception as e:
        print("Error creating info file: {}".format(e))
        return None
    return info_file_path

def info_has_softwareid(info_data, softwareid):
    for item in info_data['Members']:
        if item['SoftwareId'] == softwareid:
            return True
    return False

def main():
    parser = get_arg_parser()
    args   = parser.parse_args()
    reset_bios = False
    info_data = None
    new_fw_file_path = None

    if args.show_version:
        print(Version)
        return 0
    if not (
        args.username and args.password and args.bmc_ip
    ):
        print("Please use -h/--help to get help informations, "
              "the following arguments are required for Update: -U, -P, -H.")
        return 0
    if args.module:
        if not (args.fw_file_path or args.clear_config or args.oem_fru):
            print("Argument -F, -C or -s is required while -T is provided")
            return 0

    # Ensure a task ID is provided
    if not args.task_id:
        args.task_id = str(int(time.time() * 1000))

    if args.module:
        if not args.username or not args.password:
            print("Username -U and password -P are required for modules update")
            return 1

        if args.module == 'BUNDLE':
            if not args.ssh_username:
                args.ssh_username = args.username
            if not args.ssh_password:
                args.ssh_password = args.password

            # Only call file creation and merging functions when executing upgrade actions with -T BUNDLE
            # Create configuration file
            cfg_file_path = create_cfg_file(args.username, args.password, args.ssh_username, args.ssh_password, args.config_path, args.task_id)
            # Merge files
            new_fw_file_path = merge_files(cfg_file_path, args.fw_file_path, args.task_id)

            info_file_path = extract_info(new_fw_file_path, args.config_path, args.task_id)
            if info_file_path:
                print("Info file created at {}".format(info_file_path))
                info_data = json.load(open(info_file_path))
                if info_has_softwareid(info_data, 'config-image.bfb'):
                    reset_bios = True
    else:
        new_fw_file_path = args.fw_file_path

    try:
        dpu_update = bf_dpu_update.BF_DPU_Update(args.bmc_ip,
                                                 args.bmc_port,
                                                 args.username,
                                                 args.password,
                                                 new_fw_file_path,
                                                 args.module,
                                                 args.oem_fru,
                                                 args.skip_same_version,
                                                 args.debug,
                                                 args.output_file,
                                                 use_curl = True,
                                                 bfb_update_protocol = args.bios_update_protocol,
                                                 reset_bios = reset_bios)
        if info_data:
            dpu_update.set_info_data(info_data)

        if args.show_all_versions:
            dpu_update.show_all_versions()
            return 0

        if args.fw_file_path is not None or args.oem_fru is not None:
            dpu_update.do_update()

            print("Upgrade finished!")

        if args.config_file is not None:
            dpu_config = bf_dpu_update.BF_DPU_Update(args.bmc_ip,
                                                     args.bmc_port,
                                                     args.username,
                                                     args.password,
                                                     args.config_file,
                                                     'CONFIG',
                                                     args.oem_fru,
                                                     args.skip_same_version,
                                                     args.debug,
                                                     args.output_file,
                                                     bfb_update_protocol = args.bios_update_protocol,
                                                     use_curl = True)
            dpu_config.do_update()

        if args.clear_config:
            dpu_update.reset_config()

        return 0

    except bf_dpu_update.Err_Exception as e:
        sys.stderr.write("[Error Happened]:\n\t" + str(e) + '\n')
        if args.debug:
            import traceback
            traceback.print_exc()
        return e.err_num.value
    except Exception as e:
        sys.stderr.write("[Error Happened]:\n\t" + str(e) + '; please use -d to get detail info \n')
        if args.debug:
            import traceback
            traceback.print_exc()
        return bf_dpu_update.Err_Num.OTHER_EXCEPTION.value

if __name__ == '__main__':
    ret = main()
    sys.exit(ret)
