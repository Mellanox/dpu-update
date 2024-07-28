#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024, NVIDIA CORPORATION. All rights reserved.


import argparse
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '/src')
import bf_dpu_update


# Version of this script tool
Version = '1.0.3'


def get_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-U',             metavar="<username>",        dest="username",     type=str, required=True, help='Username of BMC')
    parser.add_argument('-P',             metavar="<password>",        dest="password",     type=str, required=True, help='Password of BMC')
    parser.add_argument('-F',             metavar="<firmware_file>",   dest="fw_file_path", type=str, required=False, help='Firmware file path (absolute/relative)')
    parser.add_argument('-T',             metavar="<module>",          dest="module",       type=str, required=False, help='The module to be updated: BMC|CEC|BIOS', choices=('BMC', 'CEC', 'BIOS'))
    parser.add_argument('-H',             metavar="<bmc_ip>",          dest="bmc_ip",       type=str, required=True, help='IP/Host of BMC')
    parser.add_argument('-C',             action='store_true',         dest="clear_config",           required=False, help='Reset to factory configuration (Only used for BMC|BIOS)')
    parser.add_argument('-o', '--output', metavar="<output_log_file>", dest="output_file",  type=str, required=False, help='Output log file')
    parser.add_argument('-p', '--port',   metavar="<bmc_port>",        dest="bmc_port",     type=str, required=False, help='Port of BMC (443 by default).')
    parser.add_argument('-v', '--version',     action='store_true',    dest="show_version",           required=False, help='Show the version of this scripts')
    parser.add_argument('--skip_same_version', action='store_true',    dest="skip_same_version",      required=False, help='Do not upgrade, if upgrade version is the same as current running version')
    parser.add_argument('--show_all_versions', action='store_true',    dest="show_all_versions",      required=False, help=argparse.SUPPRESS)
    parser.add_argument('-d', '--debug',       action='store_true',    dest="debug",                  required=False, help='Show more debug info')
    return parser


def main():
    parser = get_arg_parser()
    args   = parser.parse_args()

    if args.show_version:
        print(Version)
        return 0

    try:
        dpu_update = bf_dpu_update.BF_DPU_Update(args.bmc_ip,
                                                 args.bmc_port,
                                                 args.username,
                                                 args.password,
                                                 args.fw_file_path,
                                                 args.module,
                                                 args.skip_same_version,
                                                 args.debug,
                                                 args.output_file,
                                                 use_curl = True)

        if args.show_all_versions:
            dpu_update.show_all_versions()
            return 0

        dpu_update.do_update()
        if args.module == 'BMC':
            if args.clear_config:
                dpu_update.factory_reset_bmc()
        elif args.module == 'BIOS':
            if args.clear_config:
                dpu_update.factory_reset_bios()
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