# SharpSphere - Attacking vSphere Infrastructure

Credit [@jkcoote](https://twitter.com/jkcoote) & [@grzryc](https://github.com/grzryc)

Full walk-through and examples available [here](https://jamescoote.co.uk/introducing-sharpsphere/).

## Introduction
SharpSphere gives red teamers the ability to easily interact with the guest operating systems of virtual machines managed by vCenter. It uses the vSphere Web Services API and exposes the following functions:

- **Command & Control** - In combination with [F-Secure's C3](https://github.com/FSecureLABS/C3), SharpSphere provides C&C into VMs using VMware Tools, with no direct network connectivity to the target VM required.
- **Code Execution** - Allows arbitrary commands to be executed in the guest OS and returns the result
- **File Upload** - Allows arbitrary files to be uploaded to the guest OS
- **File Download** - Allows arbitrary files to be downloaded from the guest OS
- **List VMs** - Lists the VMs managed by vCenter that have VMware Tools running

SharpSphere supports execution through Cobalt Strike's *execute-assembly*.

## Compilation
Compiled versions can be found [here](https://github.com/JamesCooteUK/SharpSphere/releases).

If you compile yourself you'll need to use `ILMerge` to combine SharpSphere.exe and CommandLine.dll in the `Releases` folder.

## Useage
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

  --username    Required. vCenter username, i.e. administrator@vsphere.local

  --password    Required. vCenter password
```

### Code execution:
```
SharpSphere.exe execute --help

  --url              Required. vCenter SDK URL, i.e. https://127.0.0.1/sdk

  --username         Required. vCenter username, i.e. administrator@vsphere.local

  --password         Required. vCenter password

  --ip               Required. Target VM IP address

  --guestusername    Required. Username used to authenticate to the guest OS

  --guestpassword    Required. Password used to authenticate to the guest OS

  --command          Required. Command to execute

  --output           (Default: false) Flag to receive the output. Will create a temporary file in C:\Users\Public on the
                     guest to save the output. This is then downloaded and printed to the console and the file deleted.
```

### Command & Control:
```
SharpSphere.exe c2 --help

  --url              Required. vCenter SDK URL, i.e. https://127.0.0.1/sdk

  --username         Required. vCenter username, i.e. administrator@vsphere.local

  --password         Required. vCenter password

  --ip               Required. Target VM IP address

  --guestusername    Required. Username used to authenticate to the guest OS

  --guestpassword    Required. Password used to authenticate to the guest OS

  --localdir         Required. Full path to the C3 directory on this machine

  --guestdir         Required. Full path to the C3 directory on the guest OS

  --inputid          Required. Input ID configured for the C3 relay running on this machine

  --outputid         Required. Output ID configured for the C3 relay running on this machine
```

### File Upload:
```
SharpSphere.exe upload --help

  --url              Required. vCenter SDK URL, i.e. https://127.0.0.1/sdk

  --username         Required. vCenter username, i.e. administrator@vsphere.local

  --password         Required. vCenter password

  --ip               Required. Target VM IP address

  --guestusername    Required. Username used to authenticate to the guest OS

  --guestpassword    Required. Password used to authenticate to the guest OS

  --source           Required. Full path to local file to upload

  --destination      Required. Full path to location where file should be uploaded
```

### File Download:
```
>SharpSphere.exe download --help

  --url              Required. vCenter SDK URL, i.e. https://127.0.0.1/sdk

  --username         Required. vCenter username, i.e. administrator@vsphere.local

  --password         Required. vCenter password

  --ip               Required. Target VM IP address

  --guestusername    Required. Username used to authenticate to the guest OS

  --guestpassword    Required. Password used to authenticate to the guest OS

  --source           Required. Full path in the guest to the file to upload

  --destination      Required. Full path to the local directory where the file should be downloaded
```

### Future Features
1. Add support for Linux guest OS
2. Include a `--verbose` option for listing VMs
3. Add a `--quiet` flag to not mention every packet that's transferred
4. Add a `--testauth` flag to confirm guest credentials are valid
