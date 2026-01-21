# DPU-Update v1.7.2 Changelog

> **Comparison**: Current codebase vs. `dev/degrade_bfb_292_54_spec` branch

---

## Table of Contents

- [High-Level Overview](#high-level-overview)
- [Summary of Changes by Area](#summary-of-changes-by-area)
  - [1. Version Bump](#1-version-bump)
  - [2. New Console Logging System](#2-new-console-logging-system)
  - [3. Enhanced Error Reporting](#3-enhanced-error-reporting)
  - [4. SimpleUpdate API Improvements](#4-simpleupdate-api-improvements)
  - [5. Firmware Update Process Enhancements](#5-firmware-update-process-enhancements)
- [Deep-Dive: Detailed Changes](#deep-dive-detailed-changes)
  - [OobUpdate.py Changes](#oobupdatepy-changes)
  - [src/console_logger.py (New File)](#srcconsole_loggerpy-new-file)
  - [src/bf_dpu_update.py Changes](#srcbf_dpu_updatepy-changes)

---

## High-Level Overview

Version 1.7.2 introduces a significant overhaul of the logging and error reporting infrastructure. The primary focus of this release is on **user-facing clarity** and **operational reliability**:

| Metric | Before | After |
|--------|--------|-------|
| Version | 1.6 | 1.7.2 |
| Files Changed | - | 3 |
| Lines Added | - | 390 |
| Lines Removed | - | 20 |

### Key Improvements

1. **Structured Console Logging**: A new `ConsoleLogger` module provides clean separation between console output and file logging, ensuring errors are immediately visible to users.

2. **Clear Error Messages**: The `ClearErrorReporter` class formats error messages with actionable guidance, making troubleshooting significantly easier.

3. **BMC Compatibility**: Improved handling of `SimpleUpdate` API with automatic fallback when `Targets` parameter isn't supported.

4. **Better Feedback**: Enhanced progress messages and post-update wait times for firmware inventory refresh.

---

## Summary of Changes by Area

### 1. Version Bump

**File**: `OobUpdate.py`

The tool version has been updated from `1.6` to `1.7.2`, reflecting the substantial improvements in this release.

---

### 2. New Console Logging System

**File**: `src/console_logger.py` (New - 172 lines)

A completely new module following Clean Code principles with:

- **`LoggerInterface`**: Abstract base class defining the logging contract
- **`ConsoleLogger`**: Handles console-only logging (stderr for errors, stdout for info)
- **`ErrorMessageFormatter`**: Static methods for formatting clear, actionable error messages
- **`ClearErrorReporter`**: High-level error reporting with troubleshooting guidance

**Design Principles Applied**:
- Single Responsibility Principle (SRP)
- Interface Segregation Principle (ISP)
- Dependency Inversion Principle (DIP)

---

### 3. Enhanced Error Reporting

**File**: `src/bf_dpu_update.py`

Comprehensive error handling improvements across multiple areas:

| Error Category | Improvement |
|---------------|-------------|
| BMC Connection Failures | Clear message with IP and port, troubleshooting steps |
| Authentication Failures | Specific messages for locked accounts vs. invalid credentials |
| SSH Failures | Detection of permission denied, host key, and connection issues |
| Task Timeouts | Explicit timeout duration in error messages |
| Upgrade Failures | Component name and specific failure reason included |

---

### 4. SimpleUpdate API Improvements

**File**: `src/bf_dpu_update.py`

New methods and retry logic for better BMC compatibility:

- **`get_simple_update_supported_params()`**: Dynamically discovers which parameters the BMC supports
- **`is_simple_update_param_supported()`**: Helper to check individual parameter support
- **Automatic Retry**: If `Targets` parameter fails with "NotSupported" error, automatically retries without it

---

### 5. Firmware Update Process Enhancements

**File**: `src/bf_dpu_update.py`

- Improved progress messaging during firmware upload and wait operations
- Added 180-second wait for BMC FirmwareInventory refresh after firmware reset
- Better exception state handling with categorization of recoverable vs. fatal errors

---

## Deep-Dive: Detailed Changes

### OobUpdate.py Changes

```diff
- Version = '1.6'
+ Version = '1.7.2'
```

Simple version increment to reflect the new release. This version string is used in help output and logging.

---

### src/console_logger.py (New File)

This entirely new module (172 lines) implements a clean, structured logging system.

#### LoggerInterface (Abstract Base Class)

```python
class LoggerInterface(ABC):
    """Interface segregation principle: Define what loggers can do"""
    
    @abstractmethod
    def log_error(self, message: str) -> None: pass
    
    @abstractmethod
    def log_info(self, message: str) -> None: pass
    
    @abstractmethod
    def log_warning(self, message: str) -> None: pass
```

**Purpose**: Establishes a contract for any logging implementation, enabling dependency injection and testability.

#### ConsoleLogger Implementation

```python
class ConsoleLogger(LoggerInterface):
    def log_error(self, message: str) -> None:
        """Log error to stderr for immediate visibility"""
        self._write_to_console(f"ERROR: {message}", sys.stderr)
    
    def log_info(self, message: str) -> None:
        """Log info to stdout"""
        self._write_to_console(f"INFO: {message}", sys.stdout)
```

**Key Features**:
- Errors go to `stderr` for immediate visibility (even through rshim)
- Info messages go to `stdout`
- Flush after each write ensures immediate output
- Optional debug mode for verbose logging

#### ErrorMessageFormatter

```python
class ErrorMessageFormatter:
    @staticmethod
    def format_authentication_error(bmc_ip: str, username: str, 
                                   error_details: Optional[str] = None) -> str:
        # Handles locked accounts, invalid credentials, generic failures
        
    @staticmethod
    def format_connection_error(bmc_ip: str, port: Optional[int] = None) -> str:
        # Provides troubleshooting steps: verify IP, network, BMC power
        
    @staticmethod
    def format_upgrade_failure(component: str, version_info: str = "", 
                              failure_reason: Optional[str] = None) -> str:
        # Categorizes: timeout, version validation, storage space issues
        
    @staticmethod
    def format_ssh_authentication_error(bmc_ip: str, ssh_username: str) -> str:
        # SSH-specific message with SSH service verification guidance
```

**Purpose**: Centralized, consistent error message formatting with actionable user guidance.

#### ClearErrorReporter

```python
class ClearErrorReporter:
    def __init__(self, logger: LoggerInterface):
        self.logger = logger
        self.formatter = ErrorMessageFormatter()
    
    def report_authentication_failure(self, bmc_ip, username, error_details): ...
    def report_connection_failure(self, bmc_ip, port): ...
    def report_upgrade_failure(self, component, version_info, failure_reason): ...
    def report_ssh_authentication_failure(self, bmc_ip, ssh_username): ...
    def report_progress(self, operation, progress_info): ...
```

**Purpose**: High-level facade that combines logging and formatting for consistent error reporting throughout the codebase.

---

### src/bf_dpu_update.py Changes

#### 1. Initialization Changes

**Before**:
```python
def __init__(self, ...):
    # ... existing initialization ...
    pass
```

**After**:
```python
def __init__(self, ...):
    # ... existing initialization ...
    
    # Initialize console logging system
    self.console_logger = ConsoleLogger(debug=debug)
    self.error_reporter = ClearErrorReporter(self.console_logger)
```

**Impact**: Every `BF_DPU_Update` instance now has built-in clear error reporting capabilities.

---

#### 2. BMC Connection Error Handling

**Before** (lines ~240-257):
```python
except Exception as e:
    error_msg = "BMC at {} is not reachable".format(self._format_ip(self.bmc_ip))
    print("Error: {}".format(error_msg))
    self.log("Error: {}: {}".format(error_msg, str(e)))
    
    if hasattr(e, 'err_num'):
        if e.err_num == Err_Num.BMC_CONNECTION_FAIL:
            raise Err_Exception(Err_Num.BMC_CONNECTION_FAIL, 
                "BMC at {} is not reachable. Please verify the IP address...".format(...))
```

**After**:
```python
except Exception as e:
    self.error_reporter.report_connection_failure(
        self._format_ip(self.bmc_ip), 
        self.bmc_port
    )
    self.log("Connection error details: {}".format(str(e)))
    
    if hasattr(e, 'err_num'):
        if e.err_num == Err_Num.BMC_CONNECTION_FAIL:
            raise Err_Exception(Err_Num.BMC_CONNECTION_FAIL, 
                "BMC connection failed - verify IP address and network connectivity")
```

**Benefits**:
- Cleaner error messages to console via `error_reporter`
- Technical details still go to log file
- Shorter, more actionable exception messages

---

#### 3. Authentication Error Handling

**Before** (lines ~304-320):
```python
if response.status_code == 401:
    if 'Account temporarily locked out' in msg:
        raise Err_Exception(Err_Num.ACCOUNT_LOCKED, msg)
    elif 'Invalid username or password' in msg:
        raise Err_Exception(Err_Num.INVALID_USERNAME_OR_PASSWORD, msg)
```

**After**:
```python
if response.status_code == 401:
    if 'Account temporarily locked out' in msg:
        self.error_reporter.report_authentication_failure(
            self._format_ip(self.bmc_ip), 
            self.username, 
            "Account is temporarily locked. Wait and try again."
        )
        raise Err_Exception(Err_Num.ACCOUNT_LOCKED, msg)
    elif 'Invalid username or password' in msg:
        self.error_reporter.report_authentication_failure(
            self._format_ip(self.bmc_ip), 
            self.username, 
            "Invalid credentials provided"
        )
        raise Err_Exception(Err_Num.INVALID_USERNAME_OR_PASSWORD, msg)
    else:
        # Generic 401 authentication failure (NEW)
        self.error_reporter.report_authentication_failure(
            self._format_ip(self.bmc_ip), 
            self.username, 
            "Authentication failed"
        )
        raise Err_Exception(Err_Num.INVALID_USERNAME_OR_PASSWORD, "Authentication failed")
```

**Benefits**:
- Clear console error message before exception is raised
- Added catch-all for unexpected 401 responses
- User sees actionable message even if exception is caught elsewhere

---

#### 4. SimpleUpdate Parameter Discovery (New Methods)

**New Method: `get_simple_update_supported_params()`**

```python
def get_simple_update_supported_params(self):
    """
    Dynamically discover which parameters the BMC supports for SimpleUpdate.
    
    Returns:
        dict: {'supported': set of param names, 'required': set of required param names}
    """
    result = {
        'supported': {'ImageURI', 'TransferProtocol', 'Username'},
        'required': {'ImageURI'}
    }
    
    # Method 1: Check @Redfish.ActionInfo for detailed parameter info
    # Method 2: Check *@Redfish.AllowableValues annotations
    
    return result
```

**New Method: `is_simple_update_param_supported()`**

```python
def is_simple_update_param_supported(self, param_name):
    """Check if a specific parameter is supported for SimpleUpdate action."""
    params = self.get_simple_update_supported_params()
    return param_name in params['supported']
```

**Purpose**: Enables runtime discovery of BMC capabilities for better compatibility across different BMC versions.

---

#### 5. SimpleUpdate Retry Logic

**Before** (lines ~529-540):
```python
data = {
    'TransferProtocol' : protocol,
    'ImageURI'         : image_uri,
    'Targets'          : self.get_simple_update_targets(),
    'Username'         : self._get_local_user()
}
response = self._http_post(url, data=json.dumps(data), headers=headers)
```

**After**:
```python
# Build request with all standard parameters including Targets
data_with_targets = {
    'TransferProtocol' : protocol,
    'ImageURI'         : image_uri,
    'Targets'          : self.get_simple_update_targets(),
    'Username'         : self._get_local_user()
}

# First attempt: try with Targets parameter
response = self._http_post(url, data=json.dumps(data_with_targets), headers=headers)

# Check if we got a 400 error about Targets not being supported
if response.status_code == 400:
    try:
        error_info = response.json()
        error_msg = str(error_info)
        if 'Targets' in error_msg and ('NotSupported' in error_msg or 'not supported' in error_msg.lower()):
            if self.debug:
                print("BMC does not support Targets parameter, retrying without it...")

            # Retry without Targets parameter
            data_without_targets = {
                'TransferProtocol' : protocol,
                'ImageURI'         : image_uri,
                'Username'         : self._get_local_user()
            }
            response = self._http_post(url, data=json.dumps(data_without_targets), headers=headers)
    except Exception as e:
        if self.debug:
            print("Error parsing response for retry logic: {}".format(e))
```

**Benefits**:
- Automatic fallback for BMCs that don't support `Targets` parameter
- Improved compatibility without user intervention
- Debug logging for troubleshooting

---

#### 6. SSH Command Error Detection

**Before** (lines ~556-570):
```python
if rc != 0:
    if not exit_on_error:
        print("Error: Failed to run command on BMC: {}".format(output))
    else:
        raise Err_Exception(output, ...)
```

**After**:
```python
if rc != 0:
    # Detect SSH authentication failures
    if any(keyword in output.lower() for keyword in 
           ['permission denied', 'authentication failed', 'host key verification failed', 
            'connection refused', 'no route to host']):
        if self.ssh_username:
            self.error_reporter.report_ssh_authentication_failure(
                self._format_ip(self.bmc_ip), 
                self.ssh_username
            )
        else:
            self.error_reporter.report_connection_failure(
                self._format_ip(self.bmc_ip), 
                self.bmc_port
            )
    
    if not exit_on_error:
        self.console_logger.log_error(f"SSH command failed on BMC: {output}")
    else:
        raise Err_Exception(output, ...)
```

**Benefits**:
- Detects common SSH failure patterns
- Provides specific error messages for authentication vs. connection issues
- Uses structured logging instead of raw `print()`

---

#### 7. Task State Handling Improvements

**Before**:
```python
elif task_state['state'] == 'Running':
    raise Err_Exception(Err_Num.TASK_TIMEOUT, "The task {} is timeout".format(task_handle))
```

**After**:
```python
elif task_state['state'] == 'Running':
    # Report timeout
    self.error_reporter.report_upgrade_failure(
        self.module or "Firmware", 
        "", 
        f"Operation timed out after {max_second} seconds"
    )
    raise Err_Exception(Err_Num.TASK_TIMEOUT, "The task {} is timeout".format(task_handle))
```

Similar improvements for:
- Exception state handling
- Background busy errors
- Generic task failures

---

#### 8. Progress Messaging Updates

**Before**:
```python
print("Wait for update service ready")
print("Start to upload firmware")
print('OLD {} Firmware Version: \n\t{}'.format(...))
```

**After**:
```python
self.console_logger.log_info("Waiting for BMC update service to be ready...")
self.console_logger.log_info("Starting firmware upload...")
self.console_logger.log_info('OLD {} Firmware Version: {}'.format(...))
```

**Benefits**:
- Consistent message formatting with `INFO:` prefix
- Proper stream handling (stdout vs. stderr)
- Flush ensures immediate display

---

#### 9. Post-Firmware Reset Wait

**New Addition** (after firmware reset):
```python
# Wait for BMC FirmwareInventory to refresh (updates roughly once per minute)
print('Waiting for BMC FirmwareInventory to refresh')
self._sleep_with_process(180)
```

**Purpose**: BMC FirmwareInventory takes time to refresh after updates. This 180-second wait ensures accurate version reporting.

---

## Migration Notes

### For Developers

No API changes are required. The new logging system is initialized automatically in `BF_DPU_Update.__init__()`.

### For Users

- Error messages are now more descriptive and actionable
- Console output format has changed (now includes `INFO:`, `ERROR:`, `WARNING:` prefixes)
- Firmware updates may take slightly longer due to the new FirmwareInventory refresh wait

---

## Files Summary

| File | Lines Changed | Type |
|------|--------------|------|
| `OobUpdate.py` | +1, -1 | Modified |
| `src/bf_dpu_update.py` | +217, -19 | Modified |
| `src/console_logger.py` | +172 | New |

**Total**: +390 lines, -20 lines
