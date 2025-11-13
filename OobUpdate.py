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
import signal
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '/src')
import bf_dpu_update

import subprocess
import hashlib

# Version of this script tool
Version = '25.04-2.5.1'
task_dir = None
debug = False

def get_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-U',             metavar="<username>",        dest="username",     type=str, required=False, help='Username of BMC')
    parser.add_argument('-P',             metavar="<password>",        dest="password",     type=str, required=False, help='Password of BMC')
    parser.add_argument('-S',             metavar="<ssh_username>",    dest="ssh_username",     type=str, required=False, help='Username of BMC SSH access')
    parser.add_argument('-K',             metavar="<ssh_password>",    dest="ssh_password",     type=str, required=False, help='SSH password of BMC')
    parser.add_argument('-F',             metavar="<firmware_file>",   dest="fw_file_path", type=str, required=False, help='Firmware file path (absolute/relative)')
    parser.add_argument('-T',             metavar="<module>",          dest="module",       type=str, required=False, help='The module to be updated: BMC|CEC|BIOS|FRU|CONFIG|BUNDLE', choices=('BMC', 'CEC', 'BIOS', 'FRU', 'CONFIG', 'BUNDLE'))
    parser.add_argument('--with-config',  action='store_true',         dest="with_config",            required=False, help='Update the configuration image file during the BUNDLE update process. Do not use –lfwp together with this option.', default=False)
    parser.add_argument('-H',             metavar="<bmc_ip>",          dest="bmc_ip",       type=str, required=False, help='IP/Host of BMC')
    parser.add_argument('-C',             action='store_true',         dest="clear_config",           required=False, help='Reset to factory configuration (Only used for BMC|BIOS)')
    parser.add_argument('-o', '--output', metavar="<output_log_file>", dest="output_file",  type=str, required=False, help='Output log file')
    parser.add_argument('-p', '--port',   metavar="<bmc_port>",        dest="bmc_port",     type=str, required=False, help='Port of BMC (443 by default).')
    parser.add_argument('--bios_update_protocol', metavar='<bios_update_protocol>', dest="bios_update_protocol", required=False, help='BIOS update protocol: HTTP or SCP', choices=('HTTP', 'SCP'))
    parser.add_argument('--config',       metavar='<config_file>',     dest="config_file",  type=str, required=False, help='Configuration file')
    parser.add_argument('--bfcfg',        metavar='<bfcfg>',           dest="bfcfg",        type=str, required=False, help='bf.cfg - BFB configuration file')
    parser.add_argument('-s',             action='append',             metavar="<oem_fru>", dest="oem_fru",           type=str, required=False, help='FRU data in the format "Section:Key=Value"')
    parser.add_argument('-v', '--version',     action='store_true',    dest="show_version",           required=False, help='Show the version of this scripts')
    parser.add_argument('--skip_same_version', action='store_true',    dest="skip_same_version",      required=False, help='Do not upgrade, if upgrade version is the same as current running version. Relevant to BIOS|BMC|CEC modules only.')
    parser.add_argument('--show_all_versions', action='store_true',    dest="show_all_versions",      required=False, help='Show firmware versions of all modules')
    parser.add_argument('-d', '--debug',       action='store_true',    dest="debug",                  required=False, help='Show more debug info')
    parser.add_argument('-L', metavar="<path>", dest="config_path", type=str, required=False, help='Linux path to save the cfg file', default='/tmp')
    parser.add_argument('--task-id',    metavar="<task_id>",    dest="task_id",     type=str, required=False, help='Unique identifier for the task')
    parser.add_argument('--lfwp',       action='store_true',    dest="lfwp",        required=False, help='Live Firmware Update patch. Works only with BUNDLE module. Do not use  –with-config together with this option.', default=False)
    return parser

def cleanup():
    global task_dir
    if task_dir:
        if os.path.exists(task_dir):
            print("Cleaning up task directory: {}".format(task_dir))
            shutil.rmtree(task_dir)

def signal_handler(signum, frame):
    global debug
    if not debug:
        cleanup()
    sys.exit(0)

def create_random_suffix():
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(5))

def create_cfg_file(username, password, ssh_username, ssh_password, task_dir, task_id, lfwp=None, with_config=False, bfcfg=None):
    cfg_file_name = "{}_{}.cfg".format(task_id, create_random_suffix())
    cfg_file_path = os.path.join(task_dir, cfg_file_name)
    try:
        with open(cfg_file_path, 'w') as cfg_file:
            cfg_file.write('BMC_USER="{}"\n'.format(username))
            cfg_file.write('BMC_PASSWORD="{}"\n'.format(password))
            cfg_file.write('BMC_SSH_USER="{}"\n'.format(ssh_username))
            cfg_file.write('BMC_SSH_PASSWORD="{}"\n'.format(ssh_password))
            if lfwp:
                cfg_file.write('LFWP="yes"\n')
            else:
                cfg_file.write('BMC_REBOOT="yes"\n')
                cfg_file.write('CEC_REBOOT="yes"\n')
            if with_config:
                cfg_file.write('UPLOAD_CONFIG_IMAGE="yes"\n')
            else:
                cfg_file.write('UPLOAD_CONFIG_IMAGE="no"\n')

            if bfcfg:
                try:
                    with open(bfcfg, 'r') as bfcfg_file:
                        cfg_file.write(bfcfg_file.read())
                except Exception as e:
                    print("Error reading bfcfg file: {}".format(e))
                    return None
        print("Configuration file saved to {}".format(cfg_file_path))
        return cfg_file_path
    except Exception as e:
        print("Error creating configuration file: {}".format(e))
        return None

def make_lfwp_bfb(cfg_file_path, fw_file_path, task_dir, task_id):
    if not fw_file_path or not fw_file_path.endswith('.bfb'):
        return fw_file_path
    new_fw_name = "{}_{}_lfwp.bfb".format(task_id, create_random_suffix())
    new_fw_path = os.path.join(task_dir, new_fw_name)
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        os.system("{script_dir}/src/mlx-mkbfb --boot-args-v0 {cfg_file} {bfb_file} {new_bfb_file}".format(script_dir=script_dir, cfg_file=cfg_file_path, bfb_file=fw_file_path, new_bfb_file=new_fw_path))
        print("New lfwp bfb file created at {}".format(new_fw_path))
        return new_fw_path
    except Exception as e:
        print("Error making lfwp bfb file: {}".format(e))
        return None

def merge_files(cfg_file_path, fw_file_path, task_dir, task_id):
    if not cfg_file_path or not fw_file_path or not fw_file_path.endswith('.bfb'):
        return fw_file_path
    new_fw_name = "{}_{}_new.bfb".format(task_id, create_random_suffix())
    new_fw_path = os.path.join(task_dir, new_fw_name)
    try:
        with open(fw_file_path, 'rb') as f1, open(cfg_file_path, 'rb') as f2, open(new_fw_path, 'wb') as out:
            shutil.copyfileobj(f1, out)
            shutil.copyfileobj(f2, out)
        print("New merged file created at {}".format(new_fw_path))
        return new_fw_path
    except Exception as e:
        print("Error merging files: {}".format(e))
        return None

def extract_info_json(file_path, start_pattern, end_pattern):
    global debug
    # Open the binary file
    try:
        with open(file_path, 'rb') as f:
            binary_data = f.read()
    except Exception as e:
        print("Error opening file: {}".format(e))
        return None

    # Decode the binary data into a string (ignoring decoding errors)
    try:
        text_data = binary_data.decode('utf-8')
    except UnicodeDecodeError:
        text_data = binary_data.decode('utf-8', errors='ignore')

    # Find starting '{' before the start pattern
    start_idx = text_data.find(start_pattern)
    if start_idx == -1:
        if debug:
            print("Start pattern not found.")
        return None

    # Find the first '{' before the start pattern
    open_brace_idx = text_data.rfind('{', 0, start_idx)
    if open_brace_idx == -1:
        if debug:
            print("No opening brace '{' found before start pattern.")
        return None

    # Find end pattern and closing '}' after it
    end_idx = text_data.find(end_pattern, open_brace_idx)
    if end_idx == -1:
        if debug:
            print("End pattern not found.")
        return None

    # Find the first '}' after the end pattern
    close_brace_idx = text_data.find('}', end_idx)
    if close_brace_idx == -1:
        if debug:
            print("No closing brace '}' found after end pattern.")
        return None

    # Extract the JSON segment
    json_segment = text_data[open_brace_idx:close_brace_idx+1]

    return json_segment

def extract_info(new_fw_file_path, task_dir, task_id):
    start_pattern = "This JSON represents"
    end_pattern = "Members@odata.count"
    info_json = extract_info_json(new_fw_file_path, start_pattern, end_pattern)
    if not info_json:
        return None
    info_file_name = "{}_{}_info.json".format(task_id, create_random_suffix())
    info_file_path = os.path.join(task_dir, info_file_name)
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


IS_SPECIAL_TARGET_292_54_BFB = False
# Constant default config filename in the script directory.
DEFAULT_292_54_CFG_NAME = "BD-config-2.0-image.bfb"
DEFAULT_292_54_CFG_VER = '2'

def get_md5sum(file_path):
    """
    Return md5sum of a file.
    Preferred: system 'md5sum' (GNU coreutils) for a small speed edge on Linux.
    Fallback: Python hashlib (portable, no external deps).
    """
    # Try system md5sum first
    try:
        result = subprocess.run(
            ["md5sum", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        md5_value = result.stdout.strip().split()[0]  # "<md5>  <filename>"
        if len(md5_value) == 32:
            return md5_value
    except Exception:
        pass

    # Fallback to hashlib
    h = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def pick_config_bfb(args):
    """
    Resolve config bfb path by priority:
    1) Use --config if provided and exists(currently NOT USED)
    2) Use DEFAULT_292_54_CFG_NAME in script dir
    Return cfg_path
    """
    # 1) Respect explicit user input
    if getattr(args, "config_file", None):
        if os.path.exists(args.config_file):
            return args.config_file
        else:
            print("[warn] --config file not found: {}".format(args.config_file))

    # 2) Look for default name alongside the script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_cfg = os.path.join(script_dir, DEFAULT_292_54_CFG_NAME)
    if os.path.exists(default_cfg):
        return default_cfg
    # Nothing found
    return None

def main():
    parser = get_arg_parser()
    args   = parser.parse_args()
    reset_bios = False
    info_data = None
    new_fw_file_path = None
    global task_dir
    global debug
    debug = args.debug

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

        if args.fw_file_path:
            real_fw_file_path = os.path.realpath(args.fw_file_path)
            if not os.path.exists(real_fw_file_path):
                print("File {} does not exist".format(real_fw_file_path))
                return 1
            args.fw_file_path = real_fw_file_path

    # Ensure a task ID is provided
    if not args.task_id:
        args.task_id = str(int(time.time() * 1000))

    task_dir = os.path.join(args.config_path, "task_{}_{}".format(args.task_id, create_random_suffix()))
    # Create a separate temporary directory for each task
    if not os.path.exists(task_dir):
        try:
            os.makedirs(task_dir)
        except OSError as e:
            print("Error creating directory {}: {}".format(task_dir, e))
            return 1

    # ---------------------------------------------------------------------
    # Special-case policy:
    # If the firmware image MD5 is the forbidden one, ignore --with-config.
    # This uses MD5 (not filename) to prevent evasion via renaming.
    # Forbidden --with-config BFB image: 
    # BFB_292_54 MD5: 
    # 11423d3b87938567b00afbfe2cb9aa03 bf-fwbundle-2.9.2-54_25.02-prod-900-9D3B6-F2SV-PA0_Ax.bfb
    # fc73aab423c9fa4d67a383128eff4b8a bf-fwbundle-2.9.2-54_25.02-prod-900-9D3B6-F2SC-EA0_Ax.bfb
    # downgrade to 2.9.2-54 need to be separated into 2 parts: downgrade config version first, then downgrade FWbundle
    # oob DIR need to carry config BFB image
    # BFB_292_54_CONFIG_MD5(PA0 and EA0):
    # 818594da66fafca76c51d7189144435d BD-config-2.0-image.bfb
    # Need to add --with-config BFB image:
    # BFB_293_39_MD5:
    # 64b27c0fdf47d0974579a43918b56b32 bf-fwbundle-2.9.3-39_25.08-prod-900-9D3B6-F2SV-PA0_Ax.bfb
    # 6743efbd27bbe91fe59cab8035f636cd bf-fwbundle-2.9.3-39_25.08-prod-900-9D3B6-F2SC-EA0_Ax.bfb
    # ---------------------------------------------------------------------
    BFB_292_54_MD5_LIST = [
        '11423d3b87938567b00afbfe2cb9aa03',
        'fc73aab423c9fa4d67a383128eff4b8a'
    ]
    BFB_293_39_MD5_LIST = [
        '64b27c0fdf47d0974579a43918b56b32',
        '6743efbd27bbe91fe59cab8035f636cd'
    ]
    BFB_292_54_CONFIG_MD5 = '818594da66fafca76c51d7189144435d'

    bfb_filename = None
    bfb_file_md5 = None
    config_filename = None
    config_file_md5 = None
    cfg_path = None
    global IS_SPECIAL_TARGET_292_54_BFB
    global DEFAULT_292_54_CFG_NAME
    try:
        if getattr(args, 'fw_file_path', None) and os.path.exists(args.fw_file_path):
            bfb_filename = os.path.basename(args.fw_file_path)
            bfb_file_md5 = get_md5sum(args.fw_file_path)
            if bfb_file_md5 in BFB_292_54_MD5_LIST:
                if getattr(args, 'with_config', False):
                    print("Detected special image (file: {}, MD5 {}). --with-config will be ignored for this image.".format(bfb_filename, bfb_file_md5))

                IS_SPECIAL_TARGET_292_54_BFB = True
                args.with_config = False

                # check config file and MD5
                cfg_path = pick_config_bfb(args)
                if not cfg_path:
                    print("ERROR: special image (file: {}, MD5 {}). No config bfb('{}') found.".format(bfb_filename, bfb_file_md5, DEFAULT_292_54_CFG_NAME))
                    return 1
                else:
                    config_filename = os.path.basename(cfg_path)
                    config_file_md5 = get_md5sum(cfg_path)
                    if not config_file_md5 == BFB_292_54_CONFIG_MD5:
                        # not correct config.bfb provided, rejected
                        print("special image (file: {}, MD5 {}) check config file failed: (file: {}, MD5 {}) ".format(bfb_filename, bfb_file_md5, config_filename, config_file_md5))
                        return 1

                print("special image (file: {}, MD5 {}) find config file: (file: {}, MD5 {}) ".format(bfb_filename, bfb_file_md5, config_filename, config_file_md5))

            elif bfb_file_md5 in BFB_293_39_MD5_LIST:
                if not getattr(args, 'with_config', False):
                    print("Detected special image (file: {}, MD5 {}). --with-config needs to be added for this image.".format(bfb_filename, bfb_file_md5))
                args.with_config = True

    except Exception as _e:
        if debug:
            print("Warning: failed to compute md5 for '{getattr(args, 'fw_file_path', None)}': {}".format(_e))
    # ---------------------------------------------------------------------

    if args.module:
        if not args.username or not args.password:
            print("Username -U and password -P are required for modules update")
            return 1

        if args.module == 'BUNDLE':
            if not args.ssh_username or not args.ssh_password:
                print("SSH Username -S and SSH Password -K are required for BUNDLE update")
                return 1

            # Only call file creation and merging functions when executing upgrade actions with -T BUNDLE
            # Create configuration file
            cfg_file_path = create_cfg_file(args.username, args.password, args.ssh_username, args.ssh_password, task_dir, args.task_id, args.lfwp, args.with_config, args.bfcfg)
            if not cfg_file_path:
                return 1

            if args.lfwp:
                # Make lfwp bfb file
                new_fw_file_path = make_lfwp_bfb(cfg_file_path, args.fw_file_path, task_dir, args.task_id)
            else:
                # Merge files
                new_fw_file_path = merge_files(cfg_file_path, args.fw_file_path, task_dir, args.task_id)

            if not new_fw_file_path:
                return 1

            info_file_path = extract_info(new_fw_file_path, task_dir, args.task_id)
            if info_file_path:
                print("Info file created at {}".format(info_file_path))
                try:
                    info_data = json.load(open(info_file_path))
                except Exception as e:
                    print("Error loading info file: {}".format(e))
                    return 1
                if info_has_softwareid(info_data, 'config-image.bfb') and args.with_config:
                    reset_bios = True
            else:
                print("No info file found in the bundle file")
        else:
            if args.fw_file_path:
                new_fw_file_path = args.fw_file_path
    else:
        new_fw_file_path = args.fw_file_path

    try:
        if IS_SPECIAL_TARGET_292_54_BFB:
            dpu_config = bf_dpu_update.BF_DPU_Update(args.bmc_ip,
                                                     args.bmc_port,
                                                     args.username,
                                                     args.password,
                                                     args.ssh_username,
                                                     args.ssh_password,
                                                     cfg_path,
                                                     task_dir,
                                                     'CONFIG',
                                                     args.oem_fru,
                                                     args.skip_same_version,
                                                     args.debug,
                                                     args.output_file,
                                                     bfb_update_protocol = args.bios_update_protocol,
                                                     use_curl = True,
                                                     version = Version)

            dpu_config.check_bmc_availability()
            curr_config_ver = dpu_config.get_ver('CONF_IMAGE')
            print("special image (file: {}, MD5 {}) config: {}".format(bfb_filename, bfb_file_md5, curr_config_ver))
            if curr_config_ver == DEFAULT_292_54_CFG_VER:
                # current config version is same as target 292-54's config version 2.0
                print("special image (file: {}, MD5 {}) upgrade/downgrade step1: config not changed: {}, skip update".format(bfb_filename, bfb_file_md5, curr_config_ver))
            else:
                print("special image (file: {}, MD5 {}) upgrade/downgrade step1: config update start".format(bfb_filename, bfb_file_md5))

                dpu_config.do_update()

                print("special image (file: {}, MD5 {}) upgrade/downgrade step1: config update success".format(bfb_filename, bfb_file_md5))
                time.sleep(5)
                dpu_config.show_all_versions()
                time.sleep(5)

            print("special image (file: {}, MD5 {}) upgrade/downgrade step2: FWBundle update start".format(bfb_filename, bfb_file_md5))

        dpu_update = bf_dpu_update.BF_DPU_Update(args.bmc_ip,
                                                 args.bmc_port,
                                                 args.username,
                                                 args.password,
                                                 args.ssh_username,
                                                 args.ssh_password,
                                                 new_fw_file_path,
                                                 task_dir,
                                                 args.module,
                                                 args.oem_fru,
                                                 args.skip_same_version,
                                                 args.debug,
                                                 args.output_file,
                                                 use_curl = True,
                                                 bfb_update_protocol = args.bios_update_protocol,
                                                 reset_bios = reset_bios,
                                                 lfwp = args.lfwp,
                                                 version = Version)
        if info_data:
            dpu_update.set_info_data(info_data)

        if args.show_all_versions:
            dpu_update.show_all_versions()
            return 0

        mode = dpu_update.get_dpu_mode()
        if debug:
            print('DPU mode: {}'.format(mode))

        if mode == 'NicMode' and args.lfwp:
            print('Live Firmware Update patch is not supported in NIC mode')
            return 1

        if args.fw_file_path is not None or args.oem_fru is not None:
            dpu_update.do_update()

            print("Upgrade finished!")

        if IS_SPECIAL_TARGET_292_54_BFB:
            print("special image (file: {}, MD5 {}) upgrade/downgrade step2: FWBundle updated success".format(bfb_filename, bfb_file_md5))
        else:
            if args.config_file is not None:
                dpu_config = bf_dpu_update.BF_DPU_Update(args.bmc_ip,
                                                        args.bmc_port,
                                                        args.username,
                                                        args.password,
                                                        args.ssh_username,
                                                        args.ssh_password,
                                                        args.config_file,
                                                        task_dir,
                                                        'CONFIG',
                                                        args.oem_fru,
                                                        args.skip_same_version,
                                                        args.debug,
                                                        args.output_file,
                                                        bfb_update_protocol = args.bios_update_protocol,
                                                        use_curl = True,
                                                        version = Version)
                dpu_config.do_update()

        if args.clear_config:
            dpu_update.reset_config()

        return 0

    except bf_dpu_update.Err_Exception as e:
        sys.stderr.write("[Error Happened]:\n\t" + str(e) + '\n')
        if args.debug:
            import traceback
            traceback.print_exc()
        else:
            cleanup()
        return e.err_num.value
    except KeyboardInterrupt:
        print("Keyboard interrupt")
        if not args.debug:
            cleanup()
        return 1
    except Exception as e:
        sys.stderr.write("[Error Happened]:\n\t" + str(e) + '; please use -d to get detail info \n')
        if args.debug:
            import traceback
            traceback.print_exc()
        else:
            cleanup()
        return bf_dpu_update.Err_Num.OTHER_EXCEPTION.value

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == '__main__':
    ret = main()
    if not debug:
        cleanup()

    sys.exit(ret)
