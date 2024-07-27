#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024, NVIDIA CORPORATION. All rights reserved.


import time
import os
import json
import subprocess
from error_num import *


class CURL_Request(object):
    def __init__(self, url, method, command):
        self.url = url
        self.method = method
        self.headers = '<CURL Command>: ' + command
        self.body = '<See CURL Command>'


class CURL_Response(object):
    def __init__(self, resp_body, headers, request):
        self.text = resp_body
        self.url = request.url
        self.request = request
        self.headers = headers
        try:
            self.status_code = int(headers.splitlines()[0].split()[1])
            self.reason = ' '.join(headers.splitlines()[0].split()[2:])
        except:
            self.status_code = 999
            self.reason = 'Error'


    def json(self):
        return json.loads(self.text)


class HTTP_Accessor(object):
    def __init__(self, url, method, username, password, headers, timeout=(60, 60)):
        self.url = url
        self.method = method
        self.username = username
        self.password = password
        self.headers = headers
        self.timeout = timeout


    def access(self, data=None):
        return self._http_access(data=data)


    def multi_part_push(self, multi_part_general_param):
        '''
        multi_part_general_param =
        {
         "key": {
                  "data" : "xxxx.txt"
                  "type: "xxxxxx"
                  "is_file_path": true,
                },
         ...
        }
        '''
        form_param = ''
        for k in multi_part_general_param:
            v = multi_part_general_param[k]
            context_type = '' if v['type'] is None else ';type={}'.format(v['type'])
            if v['is_file_path']:
                form_param += '--form "{}=@{}{}" '.format(k, v['data'], context_type)
            else:
                form_param += "--form '{}={}{}' ".format(k, v['data'], context_type)
        return self._http_access(forms=form_param)


    def upload_file(self, file_name):
        return self._http_access(transfer=file_name)


    def _http_access(self, data=None, forms=None, transfer=None):
        header_param = ''
        if self.headers is not None:
            for k in self.headers:
                header_param += '-H "{}: {}" '.format(k, self.headers[k])

        ts = str(time.time())
        resp_body_file    = '/tmp/dpu_update_resp_body_{}.txt'.format(ts)
        resp_headers_file = '/tmp/dpu_update_resp_headers_{}.txt'.format(ts)

        output_param  = '-D {} -o {}'.format(resp_headers_file, resp_body_file)
        auth_param    = "-u '{}':'{}'".format(self.username, self.password)
        x_param       = '' if self.method == 'GET' else '-X {}'.format(self.method)
        d_param       = '' if data is None else "-d '{}'".format(data)
        T_param       = '' if transfer is None else '-T {}'.format(transfer)
        form_param    = '' if forms is None else forms
        timeout_param = '--max-time {} --connect-timeout {}'.format(self.timeout[0], self.timeout[1])

        command = 'curl -s -k {} {} {} {} {} {} {} {} {}'.format(auth_param, header_param, d_param, x_param, form_param, T_param, timeout_param, self.url, output_param)
        process   = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err  = process.communicate()
        if process.returncode != 0:
            raise Err_Exception(Err_Num.CURL_COMMAND_FAILED, 'Command "{}" failed with return code: {}, error msg: {}'.format(command, process.returncode, err.decode()))

        resp_body    = self._read_file(resp_body_file)
        resp_headers = self._read_file(resp_headers_file)
        os.system('rm -f /tmp/dpu_update_resp*')

        request  = CURL_Request(self.url, self.method, command)
        response = CURL_Response(resp_body, resp_headers, request)
        return response


    def _read_file(self, file_path):
        try:
            with open(file_path, 'r') as f:
                return f.read()
        except:
            return ''
