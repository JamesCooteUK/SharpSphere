using CommandLine;

namespace SharpSphere
{
    [Verb("list", HelpText = "List all VMs managed by this vCenter")]
    class ListOptions
    {
        [Option("url", Required = true, HelpText = "vCenter SDK URL, i.e. https://127.0.0.1/sdk")]
        public string url { get; set; }

        [Option("username", Required = false, HelpText = "vCenter username, i.e. administrator@vsphere.local. Defauls to executing user and pass-through authentication if not supplied.")]
        public string username { get; set; }

        [Option("password", Required = false, HelpText = "vCenter password. Defaults to executing user and pass-through authentication if not supplied.")]
        public string password { get; set; }

        [Option("verbose", Default = false, Required = false, HelpText = "Prints verbose output about vCenter, inc. groups and users")]
        public bool verbose { get; set; }
    }

    [Verb("dump", HelpText = "Snapshot and download memory dump file")]
    class DumpOptions
    {
        [Option("url", Required = true, HelpText = "vCenter SDK URL, i.e. https://127.0.0.1/sdk")]
        public string url { get; set; }

        [Option("username", Required = false, HelpText = "vCenter username, i.e. administrator@vsphere.local. Defaults to executing user and pass-through authentication if not supplied.")]
        public string username { get; set; }

        [Option("password", Required = false, HelpText = "vCenter password. Defaults to executing user and pass-through authentication if not supplied.")]
        public string password { get; set; }

        [Option("targetvm", Required = true, HelpText = "VM to snapshot")]
        public string targetvm { get; set; }

        [Option("snapshot", Default = false, Required = false, HelpText = "WARNING: Creates and then deletes a snapshot. If unset, SharpSphere will only extract memory from last existing snapshot, or none if no snapshots are available.")]
        public bool snapshot { get; set; }

        [Option("destination", Required = true, HelpText = "Full path to the local directory where the file should be downloaded")]
        public string destination { get; set; }
    }

    [Verb("execute", HelpText = "Execute given command in target VM")]
    class ExecuteOptions
    {
        [Option("url", Required = true, HelpText = "vCenter SDK URL, i.e. https://127.0.0.1/sdk")]
        public string url { get; set; }

        [Option("username", Required = false, HelpText = "vCenter username, i.e. administrator@vsphere.local. Defaults to executing user and pass-through authentication if not supplied.")]
        public string username { get; set; }

        [Option("password", Required = false, HelpText = "vCenter password. Defaults to executing user and pass-through authentication if not supplied.")]
        public string password { get; set; }

        [Option("ip", Required = true, HelpText = "Target VM IP address")]
        public string ip { get; set; }

        [Option("guestusername", Required = false, HelpText = "Username used to authenticate to the guest OS. Defaults to executing user and pass-through authentication if not supplied")]
        public string guestusername { get; set; }

        [Option("guestpassword", Required = false, HelpText = "Password used to authenticate to the guest OS. Defaults to executing user and pass-through authentication if not supplied")]
        public string guestpassword { get; set; }

        [Option("command", Required = true, HelpText = "Command to execute")]
        public string command { get; set; }

        [Option("output", Default = false, Required = false, HelpText = @"Receive output from your command. Will create a temporary file in outputDir on the guest to save the output. This is then downloaded and printed to the console and the file deleted")]
        public bool output { get; set; }

        [Option("outputDir", Required = false, HelpText = @"When --output is provided, this is where to store the temporary file.")]
        public string outputDir { get; set; }

        [Option("linux", Default = false, Required = false, HelpText = @"Set if target VM is Linux")]
        public bool linux { get; set; }
    }


    [Verb("upload", HelpText = "Upload file to target VM")]
    class UploadOptions
    {
        [Option("url", Required = true, HelpText = "vCenter SDK URL, i.e. https://127.0.0.1/sdk")]
        public string url { get; set; }

        [Option("username", Required = false, HelpText = "vCenter username, i.e. administrator@vsphere.local. Defaults to executing user and pass-through authentication if not supplied.")]
        public string username { get; set; }

        [Option("password", Required = false, HelpText = "vCenter password. Defaults to executing user and pass-through authentication if not supplied.")]
        public string password { get; set; }

        [Option("ip", Required = true, HelpText = "Target VM IP address")]
        public string ip { get; set; }

        [Option("guestusername", Required = false, HelpText = "Username used to authenticate to the guest OS. Defaults to executing user and pass-through authentication if not supplied")]
        public string guestusername { get; set; }

        [Option("guestpassword", Required = false, HelpText = "Password used to authenticate to the guest OS. Defaults to executing user and pass-through authentication if not supplied")]
        public string guestpassword { get; set; }

        [Option("source", Required = true, HelpText = "Full path to local file to upload")]
        public string source { get; set; }

        [Option("destination", Required = true, HelpText = "Full path to location where file should be uploaded")]
        public string destination { get; set; }
    }

    [Verb("download", HelpText = "Download file from target VM")]
    class DownloadOptions
    {
        [Option("url", Required = true, HelpText = "vCenter SDK URL, i.e. https://127.0.0.1/sdk")]
        public string url { get; set; }

        [Option("username", Required = false, HelpText = "vCenter username, i.e. administrator@vsphere.local. Defaults to executing user and pass-through authentication if not supplied.")]
        public string username { get; set; }

        [Option("password", Required = false, HelpText = "vCenter password. Defaults to executing user and pass-through authentication if not supplied.")]
        public string password { get; set; }

        [Option("ip", Required = true, HelpText = "Target VM IP address")]
        public string ip { get; set; }

        [Option("guestusername", Required = false, HelpText = "Username used to authenticate to the guest OS. Defaults to executing user and pass-through authentication if not supplied")]
        public string guestusername { get; set; }

        [Option("guestpassword", Required = false, HelpText = "Password used to authenticate to the guest OS. Defaults to executing user and pass-through authentication if not supplied")]
        public string guestpassword { get; set; }

        [Option("source", Required = true, HelpText = "Full path in the guest to the file to upload")]
        public string source { get; set; }

        [Option("destination", Required = true, HelpText = "Full path to the local directory where the file should be downloaded")]
        public string destination { get; set; }
    }

    [Verb("c2", HelpText = "Run C2 using C3's VMwareShareFile module")]
    class C2Options
    {
        [Option("url", Required = true, HelpText = "vCenter SDK URL, i.e. https://127.0.0.1/sdk")]
        public string url { get; set; }

        [Option("username", Required = false, HelpText = "vCenter username, i.e. administrator@vsphere.local. Defaults to executing user and pass-through authentication if not supplied.")]
        public string username { get; set; }

        [Option("password", Required = false, HelpText = "vCenter password. Defaults to executing user and pass-through authentication if not supplied.")]
        public string password { get; set; }

        [Option("ip", Required = true, HelpText = "Target VM IP address")]
        public string ip { get; set; }

        [Option("guestusername", Required = false, HelpText = "Username used to authenticate to the guest OS. Defaults to executing user and pass-through authentication if not supplied")]
        public string guestusername { get; set; }

        [Option("guestpassword", Required = false, HelpText = "Password used to authenticate to the guest OS. Defaults to executing user and pass-through authentication if not supplied")]
        public string guestpassword { get; set; }

        [Option("localdir", Required = true, HelpText = "Full path to the C3 directory on this machine")]
        public string localdir { get; set; }

        [Option("guestdir", Required = true, HelpText = "Full path to the C3 directory on the guest OS")]
        public string guestdir { get; set; }

        [Option("inputid", Required = true, HelpText = "Input ID configured for the C3 relay running on this machine")]
        public string inputid { get; set; }

        [Option("outputid", Required = true, HelpText = "Output ID configured for the C3 relay running on this machine")]
        public string outputid { get; set; }

    }
}
