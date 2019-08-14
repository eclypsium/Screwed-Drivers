using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ServiceProcess;

namespace LoadDriverAsService
{
    class Program
    {

        
        public static String serviceName;
        static void Main(string[] args)
        {

            if (args.Length!=1)
            {
                printArgs(); 
            }
            else
            {
                try
                {
                    serviceName = getRandomServiceName();
                    string filename = args[0];
                    createService(filename);
                    startService();
                    Console.WriteLine("Driver is loaded and service is running until you press any key");
                    Console.ReadKey();
                    stopService();
                    deleteService();
                    
                }
                catch (Exception)
                {
                    if (isServiceRunning() == ServiceControllerStatus.Running)
                    {
                        stopService();
                    }
                    else
                    {
                        Console.WriteLine("Something wrong happened, please try to fix it manually, the service name is:" + serviceName);
                        Console.WriteLine("Please remember this name before continuing");
                        Console.ReadKey();

                    }
                }
            }
        }

        private static String getRandomServiceName()
        {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var stringChars = new char[8];
            var random = new Random();

            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = chars[random.Next(chars.Length)];
            }

            return new String(stringChars);
        }

        private static void printArgs()
        {
            Console.WriteLine("USAGE:");
            Console.WriteLine("LoadDriverAsService.exe Driver.sys");

        }

        private static void runCommandLinHidden(string commandline)
        {
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.FileName = "cmd.exe";
            startInfo.Arguments = "/C "+commandline;
            process.StartInfo = startInfo;
            process.Start();
        }

        private static void createService(string filename)
        {
            runCommandLinHidden("sc create " + serviceName + " type=kernel binpath=\"" + filename + "\"");
        }

        private static void deleteService()
        {
            runCommandLinHidden("sc delete " + serviceName);
        }

        private static void startService()
        {
            runCommandLinHidden("sc start " + serviceName);
        }

        private static void stopService()
        {
            runCommandLinHidden("sc stop " + serviceName);
        }

        private static ServiceControllerStatus isServiceRunning()
        {
            ServiceController sc = new ServiceController(serviceName);
            return sc.Status;
        }
    }
}
