using CommandLine;

namespace SharpSphere
{
    [Verb("list", HelpText = "List all VMs managed by this vCenter")]
    class ListOptions
    {
        [Option("url", Required = true, HelpText = "vCenter SDK URL, i.e. https://127.0.0.1/sdk")]
        public string url { get; set; }

        [Option("username", Required = true, HelpText = "vCenter username, i.e. administrator@vsphere.local")]
        public string username { get; set; }

        [Option("password", Required = true, HelpText = "vCenter password")]
        public string password { get; set; }
    }

    [Verb("execute", HelpText = "Execute given command in target VM")]
    class ExecuteOptions
    {
        [Option("url", Required = true, HelpText = "vCenter SDK URL, i.e. https://127.0.0.1/sdk")]
        public string url { get; set; }

        [Option("username", Required = true, HelpText = "vCenter username, i.e. administrator@vsphere.local")]
        public string username { get; set; }

        [Option("password", Required = true, HelpText = "vCenter password")]
        public string password { get; set; }

        [Option("ip", Required = true, HelpText = "Target VM IP address")]
        public string ip { get; set; }

        [Option("guestusername", Required = true, HelpText = "Username used to authenticate to the guest OS")]
        public string guestusername { get; set; }

        [Option("guestpassword", Required = true, HelpText = "Password used to authenticate to the guest OS")]
        public string guestpassword { get; set; }

        [Option("command", Required = true, HelpText = "Command to execute")]
        public string command { get; set; }

        [Option("output", Default = false, Required = false, HelpText = @"Receive output from your command. Will create a temporary file in C:\Users\Public on the guest to save the output. This is then downloaded and printed to the console and the file deleted.")]
        public bool output { get; set; }
    }


    [Verb("upload", HelpText = "Upload file to target VM")]
    class UploadOptions
    {
        [Option("url", Required = true, HelpText = "vCenter SDK URL, i.e. https://127.0.0.1/sdk")]
        public string url { get; set; }

        [Option("username", Required = true, HelpText = "vCenter username, i.e. administrator@vsphere.local")]
        public string username { get; set; }

        [Option("password", Required = true, HelpText = "vCenter password")]
        public string password { get; set; }

        [Option("ip", Required = true, HelpText = "Target VM IP address")]
        public string ip { get; set; }

        [Option("guestusername", Required = true, HelpText = "Username used to authenticate to the guest OS")]
        public string guestusername { get; set; }

        [Option("guestpassword", Required = true, HelpText = "Password used to authenticate to the guest OS")]
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

        [Option("username", Required = true, HelpText = "vCenter username, i.e. administrator@vsphere.local")]
        public string username { get; set; }

        [Option("password", Required = true, HelpText = "vCenter password")]
        public string password { get; set; }

        [Option("ip", Required = true, HelpText = "Target VM IP address")]
        public string ip { get; set; }

        [Option("guestusername", Required = true, HelpText = "Username used to authenticate to the guest OS")]
        public string guestusername { get; set; }

        [Option("guestpassword", Required = true, HelpText = "Password used to authenticate to the guest OS")]
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

        [Option("username", Required = true, HelpText = "vCenter username, i.e. administrator@vsphere.local")]
        public string username { get; set; }

        [Option("password", Required = true, HelpText = "vCenter password")]
        public string password { get; set; }

        [Option("ip", Required = true, HelpText = "Target VM IP address")]
        public string ip { get; set; }

        [Option("guestusername", Required = true, HelpText = "Username used to authenticate to the guest OS")]
        public string guestusername { get; set; }

        [Option("guestpassword", Required = true, HelpText = "Password used to authenticate to the guest OS")]
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
