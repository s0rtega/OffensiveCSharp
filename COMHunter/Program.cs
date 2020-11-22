using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;

namespace COMHunter
{
    class Program
    {
        public static string usage = "Usage: COMHunter.exe <-inproc|-localserver>";

        public struct COMServer
        {
            public string CLSID;
            public string ServerPath;
            public string Type;
        }
        
        static void Main(string[] args)
        {
            List<COMServer> servers = new List<COMServer>();

            if (args.Length == 0)
            {
                servers = WMICollection("InprocServer32");
                servers.AddRange(WMICollection("LocalServer32"));
            }
            else if(args[0] == "-inproc")
            {
                servers = WMICollection("InprocServer32");
            }
            else if (args[0] == "-localserver")
            {
                servers = WMICollection("LocalServer32");
            }
            else
            {
                Console.WriteLine(usage);
                return;
            }

            foreach (COMServer server in servers)
            {
                Console.WriteLine("{0} {1} ({2})", server.CLSID, server.ServerPath, server.Type);
            }
            return;
        }

        static List<COMServer> WMICollection(string type)
        {
            List<COMServer> comServers = new List<COMServer>();
            try
            {
                ManagementObjectSearcher searcher =new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_ClassicCOMClassSetting");
                foreach (ManagementObject queryObj in searcher.Get())
                {
                    // Collect InProcServer32 values
                    string svrObj = Convert.ToString(queryObj[type]);
                    string svrObj_clid = Convert.ToString(queryObj);
                    string svr = Environment.ExpandEnvironmentVariables(svrObj).Trim('"');

                    if (!string.IsNullOrEmpty(svr)
                        && svr.ToLower().StartsWith(@"c:\") // Filter out things like combase.dll and ole32.dll
                        && !svr.ToLower().Contains(@"c:\windows\") // Ignore OS components
                        || svr.Contains(@"mscoree")
                        ) // Make sure the file exists
                    {
                       if (!svr.Contains(@"mscoree.dll")){
                            if (File.Exists(svr))
                            {
                                comServers.Add(new COMServer
                                {
                                    CLSID = queryObj["ComponentId"].ToString(),
                                    ServerPath = svr,
                                    Type = type
                                });
                            }
                        }
                        else
                        {
                            try
                            {
                                RegistryKey localMachine;
                                if (Directory.Exists("C:\\Windows\\SysWOW64"))
                                { 
                                    localMachine = RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, RegistryView.Registry64); 
                                }
                                else { 
                                    localMachine = Registry.LocalMachine;
                                }

                                String subkey = @"SOFTWARE\\Classes\\CLSID\\" + queryObj["ComponentId"].ToString()+ @"\\InprocServer32";
                                using (RegistryKey key = localMachine.OpenSubKey(subkey))
                                    {
                                    if (key != null)
                                    {
                                        Object o = key.GetValue("CodeBase");
                                        
                                        // Modify this line to tune the search
                                        if ((o != null)
                                            && (!o.ToString().ToLower().Replace("\\","/").Contains(@"c:/windows/"))
                                            )
                                        {
                                            comServers.Add(new COMServer {
                                                CLSID = queryObj["ComponentId"].ToString(),
                                                ServerPath = key.GetValue("CodeBase").ToString().Replace(@"file:///",""),
                                                Type = type
                                            });
                                        }
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine("[!] Error parsing the registry for: " + queryObj["ComponentId"].ToString());
                                Console.Write("[!] " + ex.ToString());
                            }
                        }                        
                    }
                }
            }
            catch (ManagementException ex)
            {
                Console.WriteLine("[-] An error occurred while querying for WMI data: " + ex.Message);
                return null;
            }

            // Sort by path
            comServers = comServers.OfType<COMServer>().OrderBy(x => x.ServerPath).ToList();
            return comServers;
        }
    }
}