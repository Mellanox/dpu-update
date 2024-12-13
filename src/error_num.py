#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024, NVIDIA CORPORATION. All rights reserved.


from enum import Enum


# Number to trace various error
class Err_Num(Enum):
    ERR_NONE                              = 0
    ARG_FOR_UPDATE_NOT_GIVEN              = 1
    ARG_FOR_VERSION_NOT_GIVEN             = 2
    FILE_NOT_ACCESSIBLE                   = 3
    FW_FILE_NOT_MATCH_MODULE              = 4
    BMC_CONNECTION_FAIL                   = 5
    BMC_CONNECTION_RESET                  = 6
    BMC_CONNECTION_OTHER_ERR              = 7
    ACCOUNT_LOCKED                        = 8
    INVALID_USERNAME_OR_PASSWORD          = 9
    ANOTHER_UPDATE_IS_IN_PROGRESS         = 10
    UNSUPPORTED_MODULE                    = 11
    BAD_RESPONSE_FORMAT                   = 12
    EMPTY_FW_VER                          = 13
    INVALID_STATUS_CODE                   = 14
    FAILED_TO_GET_LOCAL_KEY               = 15
    FAILED_TO_ENABLE_BMC_RSHIM            = 16
    NOT_SUPPORT_CEC_RESTART               = 17
    BMC_BACKGROUND_BUSY                   = 18
    PUBLIC_KEY_NOT_EXCHANGED              = 19
    TASK_FAILED                           = 20
    NEW_VERION_CHECK_FAILED               = 21
    FAILED_TO_GET_VER_FROM_FILE           = 22
    FAILED_TO_START_HTTP_SERVER           = 23
    NOT_SUPPORT_SIMPLE_UPDATE_PROTOCOL    = 24
    BIOS_FACTORY_RESET_FAIL               = 25
    TASK_TIMEOUT                          = 26
    PUSH_URI_NOT_FOUND                    = 27
    HTTP_FILE_SERVER_NOT_ACCESSIBLE       = 28
    INVALID_BMC_ADDRESS                   = 29
    CURL_COMMAND_FAILED                   = 30
    INVALID_INPUT_PARAMETER               = 31
    USERNAME_NOT_GIVEN                    = 32
    PASSWORD_NOT_GIVEN                    = 33
    BMC_IP_NOT_GIVEN                      = 34
    MODULE_NOT_GIVEN                      = 35
    FW_FILE_NOT_GIVEN                     = 36
    FRU_NOT_GIVEN                         = 37
    UPDATE_SERVICE_NOT_READY              = 38
    OTHER_EXCEPTION                       = 127


Err_Str = {
   Err_Num.ARG_FOR_UPDATE_NOT_GIVEN       : 'BMC IP/Username/Password, Firmware file path and Module are needed to do firmware update',
   Err_Num.ARG_FOR_VERSION_NOT_GIVEN      : 'BMC IP/Username/Password are needed to show versions of all firmwares',
   Err_Num.FILE_NOT_ACCESSIBLE            : 'File is not accessible',
   Err_Num.FW_FILE_NOT_MATCH_MODULE       : 'Firmware file is NOT for the module to update',
   Err_Num.BMC_CONNECTION_FAIL            : 'Failed to establish connection to BMC. Please check the BMC IP and port',
   Err_Num.BMC_CONNECTION_RESET           : 'Connection to BMC being reset by remove',
   Err_Num.BMC_CONNECTION_OTHER_ERR       : 'Connection failed',
   Err_Num.ACCOUNT_LOCKED                 : 'Account has been locked',
   Err_Num.INVALID_USERNAME_OR_PASSWORD   : 'Invalid username or password',
   Err_Num.ANOTHER_UPDATE_IS_IN_PROGRESS  : 'Another update is in progress',
   Err_Num.UNSUPPORTED_MODULE             : 'Unsupported updating module',
   Err_Num.BAD_RESPONSE_FORMAT            : 'Bad response format',
   Err_Num.EMPTY_FW_VER                   : 'Empty firmware version in response',
   Err_Num.INVALID_STATUS_CODE            : 'Invalid response status code',
   Err_Num.FAILED_TO_GET_LOCAL_KEY        : 'Failed to get local SSH Key',
   Err_Num.FAILED_TO_ENABLE_BMC_RSHIM     : 'Failed to enable BMC rshim',
   Err_Num.NOT_SUPPORT_CEC_RESTART        : 'CEC restart redfish API is not supported in this version',
   Err_Num.BMC_BACKGROUND_BUSY            : 'BMC is busy on background operation',
   Err_Num.PUBLIC_KEY_NOT_EXCHANGED       : 'Public key was not exchanged with BMC successfully',
   Err_Num.TASK_FAILED                    : 'Task failed',
   Err_Num.NEW_VERION_CHECK_FAILED        : 'New running version check failed',
   Err_Num.FAILED_TO_GET_VER_FROM_FILE    : 'Failed to get firmware version from file',
   Err_Num.FAILED_TO_START_HTTP_SERVER    : 'Failed to start HTTP server',
   Err_Num.NOT_SUPPORT_SIMPLE_UPDATE_PROTOCOL : 'NO supported BFB update protocol',
   Err_Num.BIOS_FACTORY_RESET_FAIL        : 'Failed to do BIOS factory reset',
   Err_Num.TASK_TIMEOUT                   : 'Task timeout',
   Err_Num.PUSH_URI_NOT_FOUND             : 'Push URI not found',
   Err_Num.HTTP_FILE_SERVER_NOT_ACCESSIBLE : 'HTTP file server is not accessible from BMC',
   Err_Num.INVALID_BMC_ADDRESS            : 'Invalid BMC Address',
   Err_Num.CURL_COMMAND_FAILED            : 'Curl command failed',
   Err_Num.INVALID_INPUT_PARAMETER        : 'The input parameter provided is invalid',
   Err_Num.USERNAME_NOT_GIVEN             : 'BMC user name is not given',
   Err_Num.PASSWORD_NOT_GIVEN             : 'BMC password is not given',
   Err_Num.BMC_IP_NOT_GIVEN               : 'BMC IP is not given',
   Err_Num.MODULE_NOT_GIVEN               : 'Module to update is not given',
   Err_Num.FW_FILE_NOT_GIVEN              : 'Firmware file is not given',
   Err_Num.FRU_NOT_GIVEN                  : 'FRU is not given',
   Err_Num.UPDATE_SERVICE_NOT_READY       : 'Update service is not ready(enabled)',
   Err_Num.OTHER_EXCEPTION                : 'Other Errors',
}


class Err_Exception(Exception):
    def __init__(self, err_num, msg=None):
        self.err_num = err_num
        self.msg     = msg
    def __str__(self):
        return Err_Str[self.err_num] + (('; ' + self.msg + '.') if self.msg is not None else '')