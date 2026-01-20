#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024, NVIDIA CORPORATION. All rights reserved.

"""
Clean console logging system that separates console output from file logging.
Follows Clean Code principles: Single Responsibility, meaningful names, and clear intent.
"""

import sys
from abc import ABC, abstractmethod
from typing import Optional


class LoggerInterface(ABC):
    """Interface segregation principle: Define what loggers can do"""
    
    @abstractmethod
    def log_error(self, message: str) -> None:
        """Log error message - should be visible to user immediately"""
        pass
    
    @abstractmethod
    def log_info(self, message: str) -> None:
        """Log informational message"""
        pass
    
    @abstractmethod
    def log_warning(self, message: str) -> None:
        """Log warning message"""
        pass


class ConsoleLogger(LoggerInterface):
    """
    Single Responsibility: Handle console-only logging (not file logging).
    This ensures errors go to console/rshim but NOT to oobupdate log.
    """
    
    def __init__(self, debug: bool = False):
        self.debug = debug
    
    def log_error(self, message: str) -> None:
        """Log error to stderr for immediate visibility"""
        self._write_to_console(f"ERROR: {message}", sys.stderr)
    
    def log_info(self, message: str) -> None:
        """Log info to stdout"""
        self._write_to_console(f"INFO: {message}", sys.stdout)
    
    def log_warning(self, message: str) -> None:
        """Log warning to stderr"""
        self._write_to_console(f"WARNING: {message}", sys.stderr)
    
    def log_debug(self, message: str) -> None:
        """Log debug info only if debug mode is enabled"""
        if self.debug:
            self._write_to_console(f"DEBUG: {message}", sys.stdout)
    
    def _write_to_console(self, message: str, stream) -> None:
        """Private method to handle actual console writing"""
        stream.write(f"{message}\n")
        stream.flush()  # Ensure immediate output


class ErrorMessageFormatter:
    """
    Single Responsibility: Format error messages in a clear, actionable way.
    Uses explanatory variables and meaningful names from Clean Code principles.
    """
    
    @staticmethod
    def format_authentication_error(bmc_ip: str, username: str, 
                                   error_details: Optional[str] = None) -> str:
        """
        Format BMC authentication error with clear, actionable message.
        
        Args:
            bmc_ip: The BMC IP address that failed
            username: The username that was used
            error_details: Optional specific error details from BMC
            
        Returns:
            Clear, actionable error message
        """
        base_message = f"BMC authentication failed for user '{username}' at {bmc_ip}"
        
        if error_details:
            if "locked" in error_details.lower():
                return f"{base_message} - Account is temporarily locked. Wait and try again."
            elif "invalid" in error_details.lower():
                return f"{base_message} - Invalid credentials. Please verify username and password."
            else:
                return f"{base_message} - {error_details}"
        
        return f"{base_message} - Please verify BMC IP, username, and password are correct."
    
    @staticmethod
    def format_connection_error(bmc_ip: str, port: Optional[int] = None) -> str:
        """Format BMC connection error with troubleshooting guidance"""
        port_info = f":{port}" if port else ""
        return (f"Cannot connect to BMC at {bmc_ip}{port_info} - "
                f"Please verify: 1) BMC IP address is correct, "
                f"2) Network connectivity exists, 3) BMC is powered on")
    
    @staticmethod
    def format_upgrade_failure(component: str, version_info: str = "", 
                              failure_reason: Optional[str] = None) -> str:
        """Format firmware upgrade failure with specific details"""
        base_message = f"{component} firmware upgrade failed"
        
        if version_info:
            base_message += f" (target version: {version_info})"
        
        if failure_reason:
            if "timeout" in failure_reason.lower():
                return f"{base_message} - Operation timed out. BMC may be busy with another task."
            elif "version" in failure_reason.lower():
                return f"{base_message} - Version validation failed. {failure_reason}"
            elif "space" in failure_reason.lower():
                return f"{base_message} - Insufficient storage space on BMC."
            else:
                return f"{base_message} - {failure_reason}"
        
        return f"{base_message} - Check BMC logs for detailed information."
    
    @staticmethod
    def format_ssh_authentication_error(bmc_ip: str, ssh_username: str) -> str:
        """Format SSH authentication error specifically"""
        return (f"SSH authentication failed for user '{ssh_username}' at {bmc_ip} - "
                f"Verify SSH credentials and ensure SSH service is enabled on BMC")


class ClearErrorReporter:
    """
    Single Responsibility: Report errors in a clear, user-friendly way.
    Dependency Inversion: Depends on LoggerInterface abstraction, not concrete implementation.
    """
    
    def __init__(self, logger: LoggerInterface):
        self.logger = logger
        self.formatter = ErrorMessageFormatter()
    
    def report_authentication_failure(self, bmc_ip: str, username: str, 
                                    error_details: Optional[str] = None) -> None:
        """Report authentication failure with clear, actionable message"""
        clear_message = self.formatter.format_authentication_error(
            bmc_ip, username, error_details
        )
        self.logger.log_error(clear_message)
    
    def report_connection_failure(self, bmc_ip: str, port: Optional[int] = None) -> None:
        """Report connection failure with troubleshooting guidance"""
        clear_message = self.formatter.format_connection_error(bmc_ip, port)
        self.logger.log_error(clear_message)
    
    def report_upgrade_failure(self, component: str, version_info: str = "", 
                             failure_reason: Optional[str] = None) -> None:
        """Report firmware upgrade failure with specific details"""
        clear_message = self.formatter.format_upgrade_failure(
            component, version_info, failure_reason
        )
        self.logger.log_error(clear_message)
    
    def report_ssh_authentication_failure(self, bmc_ip: str, ssh_username: str) -> None:
        """Report SSH authentication failure specifically"""
        clear_message = self.formatter.format_ssh_authentication_error(bmc_ip, ssh_username)
        self.logger.log_error(clear_message)
    
    def report_progress(self, operation: str, progress_info: str) -> None:
        """Report operation progress"""
        self.logger.log_info(f"{operation}: {progress_info}")
