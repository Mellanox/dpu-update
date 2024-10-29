## Dpu update Script

This repository is created only for reference code and example.

  OobUpdate.sh - BlueField DPU Update Script (out-of-band)

## Description

OobUpdate.sh is a program for updating various component firmware of BlueField DPU, like BMC, CEC and BIOS. It works from out of band, uses RedFish API exposed by BMC of DPU. The script can work from any controller host (Linux), which has available connection to the DPU BMC system.

## Usage

    OobUpdate.sh [-h] [-U <username>] [-P <password>] [-F <firmware_file>]
                 [-T <module>] [-H <bmc_ip>] [-C <clear_config>]
                 [-o <output_log_file>] [-p <bmc_port>] [-s <oem_fru>] [-v]
                 [--skip_same_version] [-d]

    optional arguments:
      -h, --help            show this help message and exit
      -U <username>         Username of BMC
      -P <password>         Password of BMC
      -F <firmware_file>    Firmware file path (absolute/relative)
      -T <module>           The module to be updated: BMC|CEC|BIOS|FRU|CONFIG
      -H <bmc_ip>           IP/Host of BMC
      -C                    Reset to factory configuration (Only used for BMC|BIOS|CONFIG)
      -o <output_log_file>, --output <output_log_file>
                            Output log file
      -p <bmc_port>, --port <bmc_port>
                            Port of BMC
      -s <oem_fru>          FRU data in the format Section:Key=Value
      -v, --version         Show the version of this scripts
      --skip_same_version   Do not upgrade, if upgrade version is the same as
                            current running version
      -d, --debug           Show more debug info

## Example
### Update BMC firmware

    # ./OobUpdate.sh -U root -P Nvidia20240604-- -H 10.237.121.98  -T BMC -F /opt/bf3-bmc-24.04-5_ipn.fwpkg
    Start to upload firmware
    Process-: 100%: ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    Restart BMC to make new firmware take effect
    Process-: 100%: ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    OLD BMC Firmware Version:
            BF-24.03-4
    New BMC Firmware Version:
            BF-24.04-5

### Update CEC firmware

    # ./OobUpdate.sh -U root -P Nvidia20240604-- -H 10.237.121.98  -T CEC -F /opt/cec1736-ecfw-00.02.0182.0000-n02-rel-debug.fwpkg
    Start to upload firmware
    Process|: 100%: ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    Restart CEC to make new firmware take effect
    Process|: 100%: ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    OLD CEC Firmware Version:
            00.02.0180.0000_n02
    New CEC Firmware Version:
            00.02.0182.0000_n02

### Update BIOS firmware

    # ./OobUpdate.sh -U root -P Nvidia20240604-- -H 10.237.121.98  -T BIOS -F /opt/BlueField-4.7.0.13127_preboot-install.bfb
    Start to upload firmware
    Process-: 100%: ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    Wait for BIOS ready
    Process-: 100%: ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    Old BIOS Firmware Version:
            ATF--v2.2(release):4.8.0-14-gc58efcd, UEFI--4.8.0-11-gbd389cc
    New BIOS Firmware Version:
            ATF--v2.2(release):4.7.0-25-g5569834, UEFI--4.7.0-42-g13081ae

### Update Config Image

    # ./OobUpdate.sh -U dingzhi -P Nvidia20240604-- -H 10.237.121.98  -T CONFIG -F /opt/BD-config-image-4.9.0.13354-1.0.0.bfb
    Start to Simple Update (HTTP)
    Process-: 100%: ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    Factory reset BMC configuration
    Process-: 100%: ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    Factory reset BIOS configuration(ResetBios) (will reboot the system)
    Process|: 100%: ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░

### Restore Config

    # ./OobUpdate.sh  -U dingzhi -P Nvidia20240604-- -H 10.237.121.98 -T CONFIG -C
    Factory reset BIOS configuration(ResetBios) (will reboot the system)
    Process-: 100%: ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░

### Update FRU data

The following OEM fields can be modified by the user:

- Product Manufacturer
- Product Serial Number
- Product Part Number
- Product Version
- Product Extra
- Product Manufacture Date (format is "DD/MM/YYYY HH:MM:SS")
- Product Asset Tag
- Product GUID (Chassis Extra in ipmitool)

If a specified FRU field is left empty value, the value for that field will default to the original Nvidia FRU information.
If a specified FRU field is not set, the OEM FRU data will remain unchanged.

To update each FRU field, use the format "Section:Key=Value". Example:
- Product Manufacturer (Product:Manufacturer)
- Product Serial Number (Product:SerialNumber)
- Product Part Number (Product:PartNumber)
- Product Version (Product:Version)
- Product Extra (Product:Extra)
- Product Manufacture Date (Product:ManufactureDate)
- Product Asset Tag (Product:AssetTag)
- Product GUID (Product:GUID)

To write the FRU with the relevant data, use the following command:

    # ./OobUpdate.sh -U root -P Nvidia20240604-- -H 10.237.121.98 -T FRU -s "Product:Manufacturer=OEM" -s "Product:SerialNumber=AB12345CD6" -s "Product:PartNumber=100-1D2B3-456V-789" -s "Product:Version=1.0" -s "Product:Extra=abc" -s "Product:ManufactureDate=05/07/2021 01:00:00" -s "Product:AssetTag=1.0.0" -s "Product:GUID=AB12345CD6"
    OEM FRU data to be updated: {
        "ProductManufacturer": "OEM",
        "ProductSerialNumber": "AB12345CD6",
        "ProductPartNumber": "100-1D2B3-456V-789",
        "ProductVersion": "1.0",
        "ProductExtra": "abc",
        "ProductManufactureDate": "05/07/2021 01:00:00",
        "ProductAssetTag": "1.0.0",
        "ProductGUID": "AB12345CD6"
    }
    OEM FRU data updated successfully.

To assign empty values to specfic fields, use the following command:

    # ./OobUpdate.sh -U root -P Nvidia20240604-- -H 10.237.121.98 -T FRU -s "Product:Manufacturer=OEM" -s "Product:SerialNumber=AB12345CD6" -s "Product:PartNumber=100-1D2B3-456V-789" -s "Product:Version=1.0" -s "Product:Extra=abc" -s "Product:ManufactureDate=05/07/2021 01:00:00" -s "Product:AssetTag=" -s "Product:GUID="
    OEM FRU data to be updated: {
        "ProductManufacturer": "OEM",
        "ProductSerialNumber": "AB12345CD6",
        "ProductPartNumber": "100-1D2B3-456V-789",
        "ProductVersion": "1.0",
        "ProductExtra": "abc",
        "ProductManufactureDate": "05/07/2021 01:00:00",
        "ProductAssetTag": "",
        "ProductGUID": ""
    }
    OEM FRU data updated successfully.

To assign empty values to all fields, use the following command:

    # ./OobUpdate.sh -U root -P Nvidia20240604-- -H 10.237.121.98 -T FRU -s "Product:Manufacturer=" -s "Product:SerialNumber=" -s "Product:PartNumber=" -s "Product:Version=" -s "Product:Extra=" -s "Product:ManufactureDate=" -s "Product:AssetTag=" -s "Product:GUID="
    OEM FRU data to be updated: {
        "ProductManufacturer": "",
        "ProductSerialNumber": "",
        "ProductPartNumber": "",
        "ProductVersion": "",
        "ProductExtra": "",
        "ProductManufactureDate": "",
        "ProductAssetTag": "",
        "ProductGUID": ""
    }
    OEM FRU data updated successfully.

To assign values to specific supported OEM fields, use the following command:

    # ./OobUpdate.sh -U root -P Nvidia20240604-- -H 10.237.121.98 -T FRU -s "Product:Manufacturer=OEM" -s "Product:SerialNumber=AB12345CD6"
    OEM FRU data to be updated: {
        "ProductManufacturer": "OEM",
        "ProductSerialNumber": "AB12345CD6"
    }
    OEM FRU data updated successfully.

To ensure the FRU writing takes effect, follow these steps and in the order listed below:
1) Run the Script Command: Set the desired OEM data by sending the script command to the BMC.
2) Reboot the DPU: This will update the SMBIOS table on the DPU, and the dmidecode output will reflect the changes.
3) Reboot the BMC: This will update the FRU information on the BMC accordingly.

## Precondition (Controller Host)
1. Avaiable connection to DPU BMC
2. Python3 is needed, with requests module installed


## Precondition (Target DPU BMC)
1. User&password of DPU BMC is workable. Default user&password need to be updated in advance
2. The BMC firmware version should be >= 24.04

## Precondition (Host in which DPU plugged)
1. Rshim on Host need to be disabled, if want to update the BIOS of DPU
