# SharpSphere - Attacking vSphere Infrastructure

Credit [@jkcoote](https://twitter.com/jkcoote) & [@grzryc](https://github.com/grzryc)

Full walk-through and examples available [here](https://jamescoote.co.uk/introducing-sharpsphere/).

## Version History
- 1.0 - Initial Release
- 2.0 - Added supported for pass-through authentication using SSPI. 
- 2.1 - Added support for Linux target VMs with --linux, and added a --verbose flag for listing vCenter users and groups

## Introduction
SharpSphere gives red teamers the ability to easily interact with the guest operating systems of virtual machines managed by vCenter. It uses the vSphere Web Services API and exposes the following functions:

- **Command & Control** - In combination with [F-Secure's C3](https://github.com/FSecureLABS/C3), SharpSphere provides C&C into VMs using VMware Tools, with no direct network connectivity to the target VM required.
- **Code Execution** - Allows arbitrary commands to be executed in the guest OS and returns the result
- **File Upload** - Allows arbitrary files to be uploaded to the guest OS
- **File Download** - Allows arbitrary files to be downloaded from the guest OS
- **List VMs** - Lists the VMs managed by vCenter that have VMware Tools running
- **Dump Memory** - Dump and download VM's memory, then manually extract credentials from LSASS offline using WinDbg and Mimikatz ([Guide](https://jamescoote.co.uk/Dumping-LSASS-with-SharpShere/))

SharpSphere supports execution through Cobalt Strike's *execute-assembly*.

## Compilation
Compiled versions can be found [here](https://github.com/JamesCooteUK/SharpSphere/releases).

## Usage
Available modules:
```
SharpSphere.exe help


  list        List all VMs managed by this vCenter

  execute     Execute given command in target VM

  c2          Run C2 using C3's VMwareShareFile module

  upload      Upload file to target VM

  download    Download file from target VM

  help        Display more information on a specific command.

  version     Display version information.

```

### List VMs:
```
SharpSphere.exe list --help 

  --url         Required. vCenter SDK URL, i.e. https://127.0.0.1/sdk

  --username    vCenter username, i.e. administrator@vsphere.local. Defauls to executing user and pass-through
                authentication if not supplied.

  --password    vCenter password. Defaults to executing user and pass-through authentication if not supplied.

  --verbose     (Default: false) Prints verbose output about vCenter, inc. groups and users

  --help        Display this help screen.

  --version     Display version information.
```

### Code execution:
```
SharpSphere.exe execute --help

  --url              Required. vCenter SDK URL, i.e. https://127.0.0.1/sdk

  --username         vCenter username, i.e. administrator@vsphere.local. Defaults to executing user and pass-through authentication if not supplied.

  --password         vCenter password. Defaults to executing user and pass-through authentication if not supplied.

  --ip               Required. Target VM IP address

  --guestusername    Username used to authenticate to the guest OS. Defaults to executing user and pass-through authentication if not supplied

  --guestpassword    Password used to authenticate to the guest OS. Defaults to executing user and pass-through authentication if not supplied

  --command          Required. Command to execute

  --output           (Default: false) Receive output from your command. Will create a temporary file in outputDir on the guest to save the output. This is then downloaded and printed to the console and the file
                     deleted

  --outputDir        When --output is provided, this is where to store the temporary file.

  --linux            (Default: false) Set if target VM is Linux

  --help             Display this help screen.

  --version          Display version information.
```

### Command & Control:
```
SharpSphere.exe c2 --help

  --url              Required. vCenter SDK URL, i.e. https://127.0.0.1/sdk

  --username         vCenter username, i.e. administrator@vsphere.local. Defaults to executing user and pass-through
                     authentication if not supplied.

  --password         vCenter password. Defaults to executing user and pass-through authentication if not supplied.

  --ip               Required. Target VM IP address

  --guestusername    Username used to authenticate to the guest OS. Defaults to executing user and pass-through
                     authentication if not supplied

  --guestpassword    Password used to authenticate to the guest OS. Defaults to executing user and pass-through
                     authentication if not supplied

  --command          Required. Command to execute

  --output           (Default: false) Receive output from your command. Will create a temporary file in outputDir on the
                     guest to save the output. This is then downloaded and printed to the console and the file deleted

  --outputDir        (Default: C:\Windows\Temp) When --output is provided, this is where to store the temporary file.
```

### File Upload:
```
SharpSphere.exe upload --help

  --url              Required. vCenter SDK URL, i.e. https://127.0.0.1/sdk

  --username         vCenter username, i.e. administrator@vsphere.local. Defaults to executing user and pass-through authentication if not supplied.

  --password         vCenter password. Defaults to executing user and pass-through authentication if not supplied.

  --ip               Required. Target VM IP address

  --guestusername    Username used to authenticate to the guest OS. Defaults to executing user and pass-through authentication if not supplied

  --guestpassword    Password used to authenticate to the guest OS. Defaults to executing user and pass-through authentication if not supplied

  --source           Required. Full path to local file to upload

  --destination      Required. Full path to location where file should be uploaded

  --help             Display this help screen.

  --version          Display version information.
```

### File Download:
```
>SharpSphere.exe download --help

  --url              Required. vCenter SDK URL, i.e. https://127.0.0.1/sdk

  --username         vCenter username, i.e. administrator@vsphere.local. Defaults to executing user and pass-through
                     authentication if not supplied.

  --password         vCenter password. Defaults to executing user and pass-through authentication if not supplied.

  --ip               Required. Target VM IP address

  --guestusername    Username used to authenticate to the guest OS. Defaults to executing user and pass-through
                     authentication if not supplied

  --guestpassword    Password used to authenticate to the guest OS. Defaults to executing user and pass-through
                     authentication if not supplied

  --source           Required. Full path in the guest to the file to upload

  --destination      Required. Full path to the local directory where the file should be downloaded
```

### Dumping Memory:
```
>SharpSphere.exe dump --help
  --url            Required. vCenter SDK URL, i.e. https://127.0.0.1/sdk

  --username       vCenter username, i.e. administrator@vsphere.local. Defaults to executing user and pass-through
                   authentication if not supplied.

  --password       vCenter password. Defaults to executing user and pass-through authentication if not supplied.

  --targetvm       Required. VM to snapshot

  --snapshot       (Default: false) WARNING: Creates and then deletes a snapshot. If unset, SharpSphere will only
                   extract memory from last existing snapshot, or none if no snapshots are available.

  --destination    Required. Full path to the local directory where the file should be downloaded
```

### Future Features
1. Add support for Linux guest OS
2. Include a `--verbose` option for listing VMs
3. Add a `--quiet` flag to not mention every packet that's transferred
4. Add a `--testauth` flag to confirm guest credentials are valid
