#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024, NVIDIA CORPORATION. All rights reserved.


import time
import re
import sys
import os
import json
import socket
import getpass
import subprocess
import stat
import datetime
from error_num import *


class BF_DPU_Update(object):
    module_resource = {
        'BMC'       : 'BMC_Firmware',
        'CEC'       : 'Bluefield_FW_ERoT',
        'ATF'       : 'DPU_ATF',
        'UEFI'      : 'DPU_UEFI',
        'BSP'       : 'DPU_BSP',
        'NIC'       : 'DPU_NIC',
        'NODE'      : 'DPU_NODE',
        'OFED'      : 'DPU_OFED',
        'OS'        : 'DPU_OS',
        'SYS_IMAGE' : 'DPU_SYS_IMAGE',
        'ARM_IMAGE' : 'golden_image_arm',
        'NIC_IMAGE' : 'golden_image_nic',
        'BOARD'     : 'DPU_BOARD'
    }


    def __init__(self, bmc_ip, bmc_port, username, password, fw_file_path, module, oem_fru, skip_same_version, debug=False, log_file=None, use_curl=True, bfb_update_protocol = None):
        self.bmc_ip            = self._parse_bmc_addr(bmc_ip)
        self.bmc_port          = bmc_port
        self.username          = username
        self.password          = password
        self.fw_file_path      = fw_file_path
        self.module            = module
        self.oem_fru           = oem_fru
        self.skip_same_version = skip_same_version
        self.debug             = debug
        self.log_file          = log_file
        self.protocol          = 'https://'
        self.redfish_root      = '/redfish/v1'
        self.process_flag      = True
        self._local_http_server_port = None
        self.use_curl          = use_curl
        self.http_accessor     = self._get_http_accessor()
        self.bfb_update_protocol = bfb_update_protocol


    def _get_prot_ip_port(self):
        port = '' if self.bmc_port is None else ':{}'.format(self.bmc_port)
        return self.protocol + self._format_ip(self.bmc_ip) + port


    def _get_url_base(self):
        return self._get_prot_ip_port() + self.redfish_root


    def _get_local_ip(self):
        if self._is_ipv4:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect((self.bmc_ip, 0))
        return s.getsockname()[0]


    def _get_local_user(self):
        return getpass.getuser()


    def _get_http_accessor(self):
        if self.use_curl:
            from http_accessor_curl import HTTP_Accessor
        else:
            from http_accessor_requests import HTTP_Accessor
        return HTTP_Accessor


    def _http_get(self, url, headers=None, timeout=(60, 60)):
        return self.http_accessor(url, 'GET', self.username, self.password, headers, timeout).access()


    def _http_post(self, url, data, headers=None, timeout=(60, 60)):
        return self.http_accessor(url, 'POST', self.username, self.password, headers, timeout).access(data)


    def _http_patch(self, url, data, headers=None, timeout=(60, 60)):
        return self.http_accessor(url, 'PATCH', self.username, self.password, headers, timeout).access(data)

    def _http_put(self, url, data, headers=None, timeout=(60, 60)):
        return self.http_accessor(url, 'PUT', self.username, self.password, headers, timeout).access(data)

    def _upload_file(self, url, file_path, headers=None, timeout=(60, 60)):
        return self.http_accessor(url, 'POST', self.username, self.password, headers, timeout).upload_file(file_path)


    def _multi_part_push(self, url, param, headers=None, timeout=(60, 60)):
        return self.http_accessor(url, 'POST', self.username, self.password, headers, timeout).multi_part_push(param)


    def _get_truncated_data(self, data):
        if len(data) > 1024:
            return data[0:1024] + '... ... [Truncated]'
        else:
            return data


    def _parse_bmc_addr(self, address):
        self.raw_bmc_addr = address

        # IPV4?
        if self._is_valid_ipv4(address):
            self._is_ipv4 = True
            return address

        # IPV6?
        if self._is_valid_ipv6(address):
            self._is_ipv4 = False
            return address

        # Host name(ipv4) ?
        ipv4 = self._get_ipv4_from_name(address)
        if ipv4 is not None:
            self._is_ipv4 = True
            return ipv4

        # Host name(ipv6) ?
        ipv6 = self._get_ipv6_from_name(address)
        if ipv6 is not None:
            self._is_ipv4 = False
            return ipv6
        raise Err_Exception(Err_Num.INVALID_BMC_ADDRESS, '{} is neither a valid IPV4/IPV6 nor a resolvable host name'.format(address))


    @staticmethod
    def _is_valid_ipv4(address):
        try:
            socket.inet_pton(socket.AF_INET, address)
            return True
        except:
            return False


    @staticmethod
    def _is_valid_ipv6(address):
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return True
        except:
            return False


    @staticmethod
    def _get_ipv4_from_name(address):
        try:
            ipv4_list = socket.getaddrinfo(address, None, socket.AF_INET)
            return ipv4_list[0][4][0]
        except:
            return None


    @staticmethod
    def _get_ipv6_from_name(address):
        try:
            ipv6_list = socket.getaddrinfo(address, None, socket.AF_INET6)
            return ipv6_list[0][4][0]
        except:
            return None


    def _format_ip(self, ip):
        if self._is_ipv4:
            return ip
        else:
            return '[{}]'.format(ip)


    def _validate_fru_date_format(self, date_str):
        try:
            datetime.datetime.strptime(date_str, "%d/%m/%Y %H:%M:%S")
            return True
        except ValueError:
            return False


    def log(self, msg, resp):
        data  = '[======== ' + msg + ' ========]: ' + '\n'
        data += '[Request Line]: ' + '\n'
        data += str(resp.request.method) + ' ' + resp.url + '\n'
        data += '[Request Headers]:' + '\n'
        data += str(resp.request.headers) + '\n'
        data += '[Request Body]:' + '\n'
        data += self._get_truncated_data(str(resp.request.body)) + '\n'
        data += "[Response status line]:" + '\n'
        data += str(resp.status_code) + ' ' + resp.reason + '\n'
        data += "[Response Headers]:" + '\n'
        data += json.dumps(str(resp.headers), indent=4) + '\n'
        data += "[Response Body]:" + '\n'
        data += resp.text + '\n'

        if self.debug:
            print(data, end='')
        if self.log_file is not None:
            with open(self.log_file, 'a') as f:
                f.write(data)


    def _handle_status_code(self, response, acceptable_codes, err_handler=None):
        if response.status_code in acceptable_codes:
            return

        try:
            msg = response.json()['error']['message']
        except:
            msg = ''

        # Raise exception for different cases
        if response.status_code == 401:
            if 'Account temporarily locked out' in msg:
                raise Err_Exception(Err_Num.ACCOUNT_LOCKED, msg)
            elif 'Invalid username or password' in msg:
                raise Err_Exception(Err_Num.INVALID_USERNAME_OR_PASSWORD, msg)

        if err_handler is not None:
            err_handler(response)

        raise Err_Exception(Err_Num.INVALID_STATUS_CODE, 'status code: {}; {}'.format(response.status_code, msg))


    def get_ver(self, module):
        url = self._get_url_base() + '/UpdateService/FirmwareInventory/' + self.module_resource[module]
        response = self._http_get(url)
        self.log('Get {} Firmware Version'.format(module), response)
        self._handle_status_code(response, [200])

        ver = ''
        try:
            ver = response.json()['Version']
        except Exception as e:
            raise Err_Exception(Err_Num.BAD_RESPONSE_FORMAT, 'Failed to extract firmware version')

        return ver


    def _extract_task_handle(self, response):
        '''
        {
            "@odata.id": "/redfish/v1/TaskService/Tasks/6",
            "@odata.type": "#Task.v1_4_3.Task",
            "Id": "6",
            "TaskState": "Running",
            "TaskStatus": "OK"
        }
        '''
        try:
            return response.json()["@odata.id"]
        except:
            raise Err_Exception(Err_Num.BAD_RESPONSE_FORMAT, 'Failed to extract task handle')


    def get_simple_update_protocols(self):
        url = self._get_url_base() + '/UpdateService'
        response = self._http_get(url)
        self.log('Get UpdateService Attribute', response)
        self._handle_status_code(response, [200])

        protocols = []
        '''
        {
          ...
          "Actions": {
            "#UpdateService.SimpleUpdate": {
              "TransferProtocol@Redfish.AllowableValues": [
                "SCP",
                "HTTP",
                "HTTPS"
              ],
            },
          }
          ...
        }
        '''
        try:
            protocols = response.json()['Actions']['#UpdateService.SimpleUpdate']['TransferProtocol@Redfish.AllowableValues']
        except Exception as e:
            raise Err_Exception(Err_Num.BAD_RESPONSE_FORMAT, 'Failed to extract SimpleUpdate protocols')
        return protocols


    def get_push_uri(self):
        url = self._get_url_base() + '/UpdateService'
        response = self._http_get(url)
        self.log('Get UpdateService Attribute', response)
        self._handle_status_code(response, [200])

        deprecated_uri = None
        multi_part_uri = None
        '''
        {
          ...
          "HttpPushUri": "/redfish/v1/UpdateService/update",
          "MultipartHttpPushUri": "/redfish/v1/UpdateService/update-multipart",
          ...
        }
        '''
        try:
            deprecated_uri = response.json()['HttpPushUri']
        except:
            deprecated_uri = None
        try:
            multi_part_uri = response.json()['MultipartHttpPushUri']
        except:
            multi_part_uri = None
        return (multi_part_uri, deprecated_uri)


    @staticmethod
    def _update_in_progress_err_handler(response):
        try:
            msg = response.json()['error']['message']
        except:
            msg = ''

        if response.status_code == 400:
            if 'An update is in progress' in msg:
                raise Err_Exception(Err_Num.ANOTHER_UPDATE_IS_IN_PROGRESS, 'Please try to update the firmware later')


    def update_bfb(self):
        protocols_supported_by_bmc = self.get_simple_update_protocols()
        # Current script only support HTTP/SCP
        protocols = []
        if 'HTTP' in protocols_supported_by_bmc:
            protocols.append('HTTP')
        if 'SCP' in protocols_supported_by_bmc:
            protocols.append('SCP')

        # Select protocol to be used
        protocol = None
        if self.bfb_update_protocol is not None:
            # Use the protocol provided by user
            if self.bfb_update_protocol not in protocols:
                raise Err_Exception(Err_Num.NOT_SUPPORT_SIMPLE_UPDATE_PROTOCOL, '{} is not in supported BFB update protocols {}'.format(self.bfb_update_protocol, protocols))
            protocol = self.bfb_update_protocol
        else:
            # Perfer to use HTTP, if user did not provide a protocol
            if 'HTTP' in protocols:
                protocol = 'HTTP'
            elif 'SCP' in protocols:
                protocol = 'SCP'
            if protocol is None:
                raise Err_Exception(Err_Num.NOT_SUPPORT_SIMPLE_UPDATE_PROTOCOL, 'The current supported BFB update protocols are {}'.format(protocols))

        return (protocol, self.update_bfb_by_protocol(protocol))


    def update_bfb_by_protocol(self, protocol):
        if protocol == 'HTTP':
            return self.update_bfb_by_http()
        elif protocol == 'SCP':
            return self.update_bfb_by_scp()


    def update_bfb_impl(self, protocol, image_uri):
        url = self._get_url_base() + '/UpdateService/Actions/UpdateService.SimpleUpdate'
        headers = {
            'Content-Type'     : 'application/json'
        }
        data = {
            'TransferProtocol' : protocol,
            'ImageURI'         : image_uri,
            'Targets'          : ['redfish/v1/UpdateService/FirmwareInventory/DPU_OS'],
            'Username'         : self._get_local_user()
        }
        response = self._http_post(url, data=json.dumps(data), headers=headers)
        self.log('Update BFB Firmware', response)
        self._handle_status_code(response, [100, 200, 202], self._update_in_progress_err_handler)
        return self._extract_task_handle(response)


    def update_bfb_by_scp(self):
        self.confirm_ssh_key_with_bmc()
        print("Start to upload BFB firmware (SCP)")
        return self.update_bfb_impl('SCP', self._format_ip(self._get_local_ip()) + '/' + os.path.abspath(self.fw_file_path))


    def http_server(self):
        debug = self.debug
        from http.server import HTTPServer, SimpleHTTPRequestHandler
        class _SimpleHTTPRequestHandler(SimpleHTTPRequestHandler):
            def log_message(self, format, *args):
                if debug:
                    super().log_message(format, *args)

        abs_dir = os.path.dirname(os.path.abspath(self.fw_file_path))
        os.chdir(abs_dir)
        if self._is_ipv4:
            _HTTPServer = HTTPServer
        else:
            class HTTPServerV6(HTTPServer):
                address_family = socket.AF_INET6
            _HTTPServer = HTTPServerV6

        httpd = _HTTPServer((self._get_local_ip(), 0), _SimpleHTTPRequestHandler)
        self._local_http_server_port = httpd.server_address[1]
        httpd.serve_forever()


    def create_http_server_thread(self):
        import threading
        thread = threading.Thread(target=self.http_server, daemon=True)
        thread.start()
        time.sleep(2) # Wait thread start and set the port.
        if self._local_http_server_port is None:
            raise Err_Exception(Err_Num.FAILED_TO_START_HTTP_SERVER)


    def update_bfb_by_http(self):
        self.create_http_server_thread()
        print("Start to upload BFB firmware (HTTP)")
        return self.update_bfb_impl('HTTP', self._format_ip(self._get_local_ip()) + ':' + str(self._local_http_server_port) + '//' + os.path.basename(self.fw_file_path))


    def update_bmc_fw_multipart(self, url):
        update_params  = {
            "ForceUpdate": not self.skip_same_version
        }
        multi_part_param = {
            'UpdateParameters' : {
                'data'         : json.dumps(update_params),
                'is_file_path' : False,
                'type'         : None
            },
            'UpdateFile'       : {
                'data'         : self.fw_file_path,
                'is_file_path' : True,
                'type'         : 'application/octet-stream'
            }
        }
        response = self._multi_part_push(url, multi_part_param)

        self.log('Update Firmware', response)
        self._handle_status_code(response, [100, 200, 202], self._update_in_progress_err_handler)
        return self._extract_task_handle(response)


    def update_bmc_fw_deprecated(self, url):
        headers = {
            'Content-Type' : 'application/octet-stream'
        }
        response = self._upload_file(url, self.fw_file_path, headers=headers)
        self.log('Update Firmware', response)
        self._handle_status_code(response, [100, 200, 202], self._update_in_progress_err_handler)
        return self._extract_task_handle(response)


    def update_bmc_fw(self):
        multi_part_uri, deprecated_uri  = self.get_push_uri()
        if multi_part_uri is not None:
            task_handle = self.update_bmc_fw_multipart(self._get_prot_ip_port() + multi_part_uri)
        elif deprecated_uri is not None:
            task_handle = self.update_bmc_fw_deprecated(self._get_prot_ip_port() + deprecated_uri)
        else:
            raise Err_Exception(Err_Num.PUSH_URI_NOT_FOUND)
        return task_handle


    def _get_task_status(self, task_handle):
        url = self._get_prot_ip_port() + task_handle
        response = self._http_get(url)
        self.log('Get Task Satatus', response)
        self._handle_status_code(response, [200])

        '''
        {
            "PercentComplete": 0,
            "StartTime": "2024-06-05T13:16:37+00:00",
            "TaskMonitor": "/redfish/v1/TaskService/Tasks/11/Monitor",
            "TaskState": "Running",
            "TaskStatus": "OK"
        }
        '''
        try:
            percent = response.json()['PercentComplete']
            state   = response.json()['TaskState']
            status  = response.json()['TaskStatus']
            message = response.json()['Messages']
            return {'state': state, 'status': status, 'percent': percent, 'message': str(message)}
        except:
            raise Err_Exception(Err_Num.BAD_RESPONSE_FORMAT, 'Failed to extract task status')


    def reboot_bmc(self):
        print("Restart BMC to make new firmware take effect")
        url = self._get_url_base() + '/Managers/Bluefield_BMC/Actions/Manager.Reset'
        headers = {
            'Content-Type' : 'application/octet-stream'
        }
        data = {
            'ResetType' : 'GracefulRestart'
        }
        response = self._http_post(url, data=json.dumps(data), headers=headers)
        self.log('Reboot BMC', response)
        self._handle_status_code(response, [200])
        self._sleep_with_process(100)


    def reboot_cec(self):
        print("Restart CEC to make new firmware take effect")
        url = self._get_url_base() + '/Chassis/Bluefield_ERoT/Actions/Chassis.Reset'
        headers = {
            'Content-Type' : 'application/json'
        }
        data = {
            'ResetType' : 'GracefulRestart'
        }
        response = self._http_post(url, data=json.dumps(data), headers=headers)
        self.log('Reboot CEC', response)
        self._handle_status_code(response, [200, 400])
        if response.status_code == 400:
            raise Err_Exception(Err_Num.NOT_SUPPORT_CEC_RESTART, 'Please use power cycle of the whole system instead')

        self._sleep_with_process(120)


    def factory_reset_bmc(self):
        print("Factory reset BMC configuration")
        url = self._get_url_base() + '/Managers/Bluefield_BMC/Actions/Manager.ResetToDefaults'
        headers = {
            'Content-Type' : 'application/json'
        }
        data = {
            'ResetToDefaultsType' : 'ResetAll'
        }
        response = self._http_post(url, data=json.dumps(data), headers=headers)
        self.log('Factory Reset BMC', response)
        self._handle_status_code(response, [200])
        self._sleep_with_process(100)


    def _print_process(self, percent):
        print('\r', end='')
        flag = '|' if self.process_flag else '-'
        self.process_flag = not self.process_flag
        print('Process%s: %3d%%:'%(flag, percent), '░' * (percent // 2), end='')


    def _sleep_with_process_with_percent(self, sec, start_percent=0, end_percent=100):
        for i in range(1, sec+1):
            time.sleep(1)
            self._print_process(start_percent + ((i * (end_percent - start_percent)) // sec))


    def _sleep_with_process(self, sec):
        self._sleep_with_process_with_percent(sec)
        print()


    def _extract_ver_from_fw_file(self, pattern):
        file_name = os.path.basename(self.fw_file_path)
        match     = re.search(pattern, file_name)
        substring = match.group(0)
        return substring


    def extract_cec_ver_from_fw_file(self):
        return self._extract_ver_from_fw_file(r'\d\d.\d\d.\d\d\d\d.\d\d\d\d')


    def extract_bmc_ver_from_fw_file(self):
        return self._extract_ver_from_fw_file(r'\d\d.\d\d-\d')


    def extract_atf_uefi_ver_from_fw_file(self):
        command = 'strings {} | grep -m 1 "(\(release\|debug\))"'.format(self.fw_file_path)
        process   = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        if process.returncode != 0:
            raise Err_Exception(Err_Num.FAILED_TO_GET_VER_FROM_FILE, 'Command "{}" failed with return code {}'.format(command, process.returncode))

        return str(out.decode()).strip()


    def is_fw_file_for_bmc(self):
        command  = 'strings {} | grep -i apfw'.format(self.fw_file_path)
        process  = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        if process.returncode != 0:
            return False
        return True


    def is_fw_file_for_cec(self):
        command  = 'strings {} | grep -i ecfw'.format(self.fw_file_path)
        process  = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        if process.returncode != 0:
            return False
        return True


    def is_fw_file_for_atf_uefi(self):
        try:
            self.extract_atf_uefi_ver_from_fw_file()
        except:
            return False
        return True


    # return True:  task completed successfully
    # return False: task cancelled for skip_same_version
    def _wait_task(self, task_handle, max_second=15*60, check_step=10, err_handler=None):
        # Check the task status within a loop
        for i in range(1, max_second//check_step + 1):
            task_state = self._get_task_status(task_handle)
            if task_state['state'] != "Running":
                break
            self._print_process(task_state['percent'])
            time.sleep(check_step)

        # Check the task is completed successfully
        if task_state['state'] == 'Completed' and task_state['status'] == 'OK' and task_state['percent'] == 100:
            self._print_process(100)
            print()
        elif task_state['state'] == 'Running':
            raise Err_Exception(Err_Num.TASK_TIMEOUT, "The task {} is timeout".format(task_handle))
        else:
            if err_handler is not None:
                err_handler(task_state)

            if 'Component image is identical' in task_state['message']:
                return False
            elif 'Wait for background copy operation' in task_state['message']:
                raise Err_Exception(Err_Num.BMC_BACKGROUND_BUSY, 'Please try to update the firmware later')
            raise Err_Exception(Err_Num.TASK_FAILED, task_state['message'])
        return True


    def validate_arg_for_update(self):
        if any(v is None for v in (self.username, self.password, self.fw_file_path, self.module, self.bmc_ip)):
            raise Err_Exception(Err_Num.ARG_FOR_UPDATE_NOT_GIVEN)

        if not os.access(self.fw_file_path, os.R_OK):
            raise Err_Exception(Err_Num.FILE_NOT_ACCESSIBLE, 'Firmware file: {}'.format(self.fw_file_path))

        if self.log_file is not None and not os.access(self.log_file, os.W_OK) and not os.access(os.path.abspath(os.path.dirname(self.log_file)), os.W_OK):
            raise Err_Exception(Err_Num.FILE_NOT_ACCESSIBLE, 'Log file: {}'.format(self.log_file))
        return True


    def is_bmc_background_copy_in_progress(self):
        url = self._get_url_base() + '/Chassis/Bluefield_ERoT'
        response = self._http_get(url)
        self.log('Get ERoT status', response)
        self._handle_status_code(response, [200])

        '''
        {
          ...
          "Oem": {
            "Nvidia": {
              "@odata.type": "#NvidiaChassis.v1_0_0.NvidiaChassis",
              "AutomaticBackgroundCopyEnabled": true,
              "BackgroundCopyStatus": "Completed",
              "InbandUpdatePolicyEnabled": true
            }
          },
          ...
        }
        '''
        status = ''
        try:
            status = response.json()['Oem']['Nvidia']['BackgroundCopyStatus']
        except Exception as e:
            raise Err_Exception(Err_Num.BAD_RESPONSE_FORMAT, 'Failed to extract BackgroundCopyStatus')

        if status != 'Completed':
            return True
        else:
            return False


    def update_bmc_or_cec(self, is_bmc):
        self.validate_arg_for_update()

        # Check firmare file is for BMC/CEC
        correct_file = self.is_fw_file_for_bmc() if is_bmc else self.is_fw_file_for_cec()
        if not correct_file:
            raise Err_Exception(Err_Num.FW_FILE_NOT_MATCH_MODULE)

        old_ver = self.get_ver('BMC') if is_bmc else self.get_ver('CEC')
        if old_ver == '':
            raise Err_Exception(Err_Num.EMPTY_FW_VER, 'Get empty {} version'.format('BMC' if is_bmc else 'CEC'))

        if self.is_bmc_background_copy_in_progress():
            raise Err_Exception(Err_Num.BMC_BACKGROUND_BUSY, 'Please try to update the firmware later')

        # Start firmware update task
        print("Start to upload firmware")
        task_handle = self.update_bmc_fw()
        ret = self._wait_task(task_handle, max_second=(20*60 if is_bmc else 4*60), check_step=(10 if is_bmc else 2))
        if not ret:
            print("Skip updating the same version: {}".format(old_ver))
            return

        # Reboot bmc/cec
        self.reboot_bmc() if is_bmc else self.reboot_cec()

        new_ver = self.get_ver('BMC') if is_bmc else self.get_ver('CEC')
        print('OLD {} Firmware Version: \n\t{}'.format(('BMC' if is_bmc else 'CEC'), old_ver))
        print('New {} Firmware Version: \n\t{}'.format(('BMC' if is_bmc else 'CEC'), new_ver))


    def is_rshim_enabled_on_bmc(self):
        url = self._get_url_base() + '/Managers/Bluefield_BMC/Oem/Nvidia'
        headers = {
            'Content-Type' : 'application/json'
        }
        response = self._http_get(url, headers=headers)
        self.log('Get rshim enable state', response)
        self._handle_status_code(response, [200])

        try:
            return response.json()['BmcRShim']['BmcRShimEnabled']
        except:
            raise Err_Exception(Err_Num.BAD_RESPONSE_FORMAT, 'Failed to extract BmcRShimEnabled')


    def enable_rshim_on_bmc(self, enable):
        url = self._get_url_base() + '/Managers/Bluefield_BMC/Oem/Nvidia'
        headers = {
            'Content-Type' : 'application/json'
        }
        data = {
            "BmcRShim": { "BmcRShimEnabled": enable }
        }
        response = self._http_patch(url, json.dumps(data), headers=headers)
        self.log('{} rshim on BMC'.format("Enable" if enable else "Disable"), response)
        self._handle_status_code(response, [200])


    def try_enable_rshim_on_bmc(self):
        if self.is_rshim_enabled_on_bmc():
            return True
        print("Try to enable rshim on BMC")
        self.enable_rshim_on_bmc(True)
        self._sleep_with_process_with_percent(10, 0, 30)
        if self.is_rshim_enabled_on_bmc():
            self._sleep_with_process_with_percent(1, 30, 100)
            print()
            return True

        # Try again if failed
        self.enable_rshim_on_bmc(False)
        self._sleep_with_process_with_percent(10, 30, 60)
        self.enable_rshim_on_bmc(True)
        self._sleep_with_process_with_percent(10, 60, 90)
        if self.is_rshim_enabled_on_bmc():
            self._sleep_with_process_with_percent(1, 90, 100)
            print()
            return True
        print()
        return False


    def _wait_for_bios_ready(self):
        print('Wait for BIOS ready')
        for i in range(1, 101):
            ver = self.get_ver('ATF')
            if ver != '':
                self._print_process(100)
                break
            else:
                self._print_process(i)
                time.sleep(4)
        print()


    def get_local_user_ssh_pub_key(self):
        command = 'ssh-keyscan {}'.format(self._get_local_ip())
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        if process.returncode != 0:
            raise Err_Exception(Err_Num.FAILED_TO_GET_LOCAL_KEY, 'Command "{}" failed with return code {}'.format(command, process.returncode))

        '''
        127.0.0.1 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLxvoG8lUk0CyiQ2Jk9IlTlrESlRtLzyIhQnPsXe5//YWl5nHa6oTSbkIlwk090tchoUi9nwFtTDE5Lihs1qJEc=
        127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPzhBRfJL2pZ6LNikFnlBg7iqYXh7BDbQpfg9f1R7nch
        '''
        try:
            key_list = out.decode().split('\n')
            ret_list = []
            for key in key_list:
                if key.strip() == '':
                    continue
                ret_list.append(' '.join(key.split(' ')[1:]))
            if len(ret_list) == 0:
                raise Err_Exception(Err_Num.FAILED_TO_GET_LOCAL_KEY)
            return ret_list
        except:
            raise Err_Exception(Err_Num.FAILED_TO_GET_LOCAL_KEY, 'There may be no ssh-key locally (for user {}). Please run ssh-keygen firstly'.format(self._get_local_user()))


    def exchange_ssh_key_with_bmc(self, local_key):
        url = self._get_url_base() + "/UpdateService/Actions/Oem/NvidiaUpdateService.PublicKeyExchange"
        headers = {
            'Content-Type' : 'application/json'
        }
        msg = {
          "RemoteServerIP"        : self._get_local_ip(),
          "RemoteServerKeyString" : local_key,
        }
        response = self._http_post(url, data=json.dumps(msg), headers=headers)
        self.log('Exchange SSH key with BMC', response)
        self._handle_status_code(response, [200])

        '''
        {
            "@Message.ExtendedInfo":
            [
                {
                    "@odata.type": "#Message.v1_1_1.Message",
                    "Message": "Please add the following public
                    key info to ~/.ssh/authorized_keys on the
                    remote server",
                    "MessageArgs": [
                        "<type> <bmc_public_key> root@dpu-bmc"
                    ]
                },
                {
                    ....
                }
            ]
        }
        '''
        try:
            return response.json()['@Message.ExtendedInfo'][0]['MessageArgs'][0]
        except:
            raise Err_Exception(Err_Num.BAD_RESPONSE_FORMAT, 'Failed to extract BMC SSH key')


    def is_bmc_key_in_local_authorized_keys(self, bmc_key):
        file_path = os.path.expanduser("~") + '/.ssh/authorized_keys'
        process = subprocess.Popen('grep "{}" {}'.format(bmc_key, file_path), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        if process.returncode != 0:
            return False
        return True


    def set_bmc_key_into_local_authorized_keys(self, bmc_key):
        file_path = os.path.expanduser("~") + '/.ssh/authorized_keys'

        # Check and set write permission for ~/.ssh/authorized_keys
        old_permission = None
        if not os.access(file_path, os.W_OK):
            old_permission = os.stat(file_path).st_mode
            os.chmod(file_path, old_permission | stat.S_IWUSR)

        # Append the bmc key into authorized_keys
        with open(file_path, 'a') as f:
            f.write(bmc_key + '\n')

        # Recover the permission
        if old_permission is not None:
            os.chmod(file_path, old_permission)
            old_permission = os.stat(file_path).st_mode


    def confirm_ssh_key_with_bmc(self):
        local_keys = self.get_local_user_ssh_pub_key()
        for local_key in local_keys:
            bmc_key = self.exchange_ssh_key_with_bmc(local_key)
            if not self.is_bmc_key_in_local_authorized_keys(bmc_key):
                self.set_bmc_key_into_local_authorized_keys(bmc_key)


    def update_bios(self):
        self.validate_arg_for_update()

        if not self.is_fw_file_for_atf_uefi():
            raise Err_Exception(Err_Num.FW_FILE_NOT_MATCH_MODULE)

        # Skip the same firmware version, if need
        cur_atf_ver  = self.get_ver('ATF')
        cur_uefi_ver = self.get_ver('UEFI')
        if cur_atf_ver is None or cur_uefi_ver is None:
            raise Err_Exception(Err_Num.EMPTY_FW_VER, 'Get empty ATF/UEFI version')

        # Currently, we can only extract atf version from the fw file.
        # So, only do the same_version_check on atf version. Given the
        # assumption that atf verion and uefi version should change at
        # the same time within a package.
        fw_file_atf_ver = self.extract_atf_uefi_ver_from_fw_file()
        if self.skip_same_version and cur_atf_ver in fw_file_atf_ver:
            print('Skip updating the same firmware version: ATF--{} UEFI--{}'.format(cur_atf_ver, cur_uefi_ver))
            return

        # Enable rshim on BMC
        if not self.try_enable_rshim_on_bmc():
            raise Err_Exception(Err_Num.FAILED_TO_ENABLE_BMC_RSHIM, 'Please make sure rshim on Host side is disabled')

        protocol, task_handle = self.update_bfb()

        def err_handler(task_state):
            if protocol == "SCP" and "Please provide server's public key using PublicKeyExchange" in task_state['message']:
                raise Err_Exception(Err_Num.PUBLIC_KEY_NOT_EXCHANGED)
            elif protocol == "HTTP" and "Check and restart server's web service" in task_state['message']:
                raise Err_Exception(Err_Num.HTTP_FILE_SERVER_NOT_ACCESSIBLE, "Server address: {}:{}".format(self._format_ip(self._get_local_ip()), self._local_http_server_port))

        self._wait_task(task_handle, max_second=20*60, check_step=2, err_handler=err_handler)
        self._wait_for_bios_ready()

        # Verify new version is the same as the fw file version
        new_atf_ver  = self.get_ver('ATF')
        new_uefi_ver = self.get_ver('UEFI')
        if new_atf_ver not in fw_file_atf_ver:
            raise Err_Exception(Err_Num.NEW_VERION_CHECK_FAILED, 'New BIOS version is not the version we want to update')
        print('Old {} Firmware Version: \n\tATF--{}, UEFI--{}'.format('BIOS', cur_atf_ver, cur_uefi_ver))
        print('New {} Firmware Version: \n\tATF--{}, UEFI--{}'.format('BIOS', new_atf_ver, new_uefi_ver))
        return True


    def send_factory_reset_bios(self):
        url = self._get_url_base() + '/Systems/Bluefield/Bios/Settings'
        headers = {
            'Content-Type' : 'application/json'
        }
        data = {
            'Attributes': {
                'ResetEfiVars': True,
            },
        }
        response = self._http_patch(url, data=json.dumps(data), headers=headers)
        self.log('Factory Reset BIOS', response)

        def err_handler(response):
            if response.status_code == 400:
                raise Err_Exception(Err_Num.BIOS_FACTORY_RESET_FAIL, 'Typically, it was caused for not supporting redfish factory reset in this version')

        self._handle_status_code(response, [200], err_handler)


    def reboot_system(self):
        url = self._get_url_base() + '/Systems/Bluefield/Actions/ComputerSystem.Reset'
        headers = {
            'Content-Type' : 'application/json'
        }
        data = {
            'ResetType': 'GracefulRestart'
        }
        response = self._http_post(url, data=json.dumps(data), headers=headers)
        self.log('Reboot BIOS', response)
        self._handle_status_code(response, [200, 204])


    def get_system_power_state(self):
        url = self._get_url_base() + '/Systems/Bluefield'
        response = self._http_get(url)
        self.log('Get System State', response)
        self._handle_status_code(response, [200])

        state = ''
        try:
            state = response.json()['PowerState']
        except Exception as e:
            raise Err_Exception(Err_Num.BAD_RESPONSE_FORMAT, 'Failed to extract system power state')
        return state


    def _wait_for_system_power_on(self, start_progress, end_progress):
        pre_state = self.get_system_power_state()
        for i in range(start_progress+1, end_progress+1):
            new_state = self.get_system_power_state()
            # Since, after reboot command send, the state is changing as following:
            # ...->On->Paused->PoweringOn->On
            # So, we need following two conditions to judge whether the system is On again
            if new_state != pre_state and new_state  == 'On':
                self._print_process(end_progress)
                break
            else:
                self._print_process(i)
                time.sleep(4)
            pre_state = new_state


    def factory_reset_bios(self):
        print("Factory reset BIOS configuration (will reboot the system)")
        self.send_factory_reset_bios()
        # Reboot twice is needed, according to the workflow
        self.reboot_system()
        self._wait_for_system_power_on(0, 50)
        self.reboot_system()
        self._wait_for_system_power_on(50, 100)
        print()


    def update_oem_fru(self):
        """
        Update the OEM FRU data with the provided key-value pairs in the format 'Section:Key=Value'
        """

        # Check if the user has set the parameter in self.oem_fru
        if not self.oem_fru:
            raise Err_Exception(Err_Num.INVALID_INPUT_PARAMETER, "No OEM FRU data provided. Please set the parameter for OEM FRU.")
        oem_fru_dict = {}
        if self.debug:
            print("OEM FRU data to be updated:", self.oem_fru)
        # Process each item in the provided OEM FRU data
        for item in self.oem_fru:
            try:
                section_key, value = item.split('=')
                section, key = section_key.split(':')
                combined_key = section + key
                # Check if the value exceeds 63 characters
                if len(value) > 63:
                    raise Err_Exception(Err_Num.INVALID_INPUT_PARAMETER, "Value for {} exceeds 63 characters: {}".format(section_key, value))
                oem_fru_dict[combined_key] = value
                # Validate ManufactureDate format
                if section_key == 'Product:ManufactureDate' and value and not self._validate_fru_date_format(value):
                    raise Err_Exception(Err_Num.INVALID_INPUT_PARAMETER, "Invalid date format for ManufactureDate. Expected format: DD/MM/YYYY HH:MM:SS")
                if self.debug:
                    print("Updated FRU field: {} with value: {}".format(section_key, value))
            except ValueError:
                raise Err_Exception(Err_Num.INVALID_INPUT_PARAMETER, "Invalid format for OEM FRU data: {}. Expected format 'Section:Key=Value'".format(item))

        print("OEM FRU data to be updated:", json.dumps(oem_fru_dict, indent=4))

        # Construct the URL for the HTTP PUT request
        url = self._get_url_base() + '/Systems/Bluefield/Oem/Nvidia'
        headers = {'Content-Type': 'application/json'}

        # Send the HTTP PUT request to update the OEM FRU data
        response = self._http_put(url, data=json.dumps(oem_fru_dict), headers=headers)
        if response.status_code != 200:
            raise Err_Exception(Err_Num.INVALID_STATUS_CODE, "Failed to update OEM FRU data, status code: {}".format(response.status_code))
        print("OEM FRU data updated successfully.")


    def do_update(self):
        if self.module == 'BMC' or self.module == "CEC":
            self.update_bmc_or_cec((self.module == 'BMC'))
        elif self.module == 'BIOS':
            self.update_bios()
        elif self.module == 'FRU':
            self.update_oem_fru()
        else:
            raise Err_Exception(Err_Num.UNSUPPORTED_MODULE, "Unsupported module: {}".format(self.module))


    def show_all_versions(self):
        if any(v is None for v in (self.username, self.password, self.bmc_ip)):
            raise Err_Exception(Err_Num.ARG_FOR_VERSION_NOT_GIVEN)

        vers = {}
        for module, resouce in self.module_resource.items():
            vers[module] = self.get_ver(module)

        for module, ver in vers.items():
            print("%10s : %40s"%(module, ver))
