#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024, NVIDIA CORPORATION. All rights reserved.


"""
python3 -m pip install requests
or install from local packages:
python3 -m pip install --no-index --find-links=./packages requests
"""

from error_num import *
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import requests.packages.urllib3.util.ssl_
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL'


class HTTP_Accessor(object):
    def __init__(self, url, method, username, password, headers, timeout=(60, 60)):
        self.url = url
        self.method = method
        self.username = username
        self.password = password
        self.headers = headers
        self.timeout = timeout


    def access(self, data=None):
        if self.method == 'GET':
            return self._http_get()
        elif self.method == 'POST':
            return self._http_post(data=data)
        elif self.method == 'PATCH':
            return self._http_patch(data=data)


    def multi_part_push(self, multi_part_general_param):
        '''
        multi_part_general_param =
        {
         "name": {
                  "data" : "xxxx.txt"
                  "is_file_path": true,
                  "type: "xxxxxx"
                 },
         ...
        }
        '''
        files = {}
        for k in multi_part_general_param:
            v = multi_part_general_param[k]
            files[k] = open(v['data'], 'rb') if v['is_file_path'] else v['data']
        return self._http_post(files=files)


    def upload_file(self, file_name):
        return self._http_post(data=open(file_name, 'rb'))


    def connection_exception(func):
        def wrapper(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except requests.exceptions.ConnectTimeout as timeout:
                raise Err_Exception(Err_Num.BMC_CONNECTION_FAIL)
            except requests.exceptions.ConnectionError as connect_err:
                raise Err_Exception(Err_Num.BMC_CONNECTION_RESET)
            except Exception as e:
                raise Err_Exception(Err_Num.BMC_CONNECTION_OTHER_ERR, str(e))
        return wrapper


    @connection_exception
    def _http_get(self):
        return requests.get(self.url,
                            headers=self.headers,
                            auth=(self.username, self.password),
                            verify=False,
                            timeout=self.timeout)


    @connection_exception
    def _http_post(self, data=None, files=None):
        return requests.post(self.url,
                             data=data,
                             files=files,
                             headers=self.headers,
                             auth=(self.username, self.password),
                             verify=False,
                             timeout=self.timeout)


    @connection_exception
    def _http_patch(self, data):
        return requests.patch(self.url,
                              data=data,
                              headers=self.headers,
                              auth=(self.username, self.password),
                              verify=False,
                              timeout=self.timeout)
