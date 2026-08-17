using System;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Principal;
using System.Threading;
using PacketDotNet;
using SharpPcap;

class Program
{
    private static string pingTargetHost = "8.8.8.8";
    private static long currentPingMs = -1;
    private static bool keepPinging = true;

    static void Main(string[] args)
    {
        if (!IsAdministrator())
        {
            var processInfo = new ProcessStartInfo
            {
                FileName = Process.GetCurrentProcess().MainModule.FileName,
                UseShellExecute = true,
                Verb = "runas"
            };

            try
            {
                Process.Start(processInfo);
            }
            catch
            {
                Console.WriteLine("Пользователь отказался от предоставления прав администратора.");
            }

            return;
        }

        Console.Title = "Prantecer";
        Console.Clear();
        Console.ForegroundColor = ConsoleColor.White;

        // Ввод хоста для ping
        Console.Write("Введите IP/домен для выполнения ping (нажмите Enter для 8.8.8.8): ");
        string inputHost = Console.ReadLine()?.Trim();
        if (!string.IsNullOrEmpty(inputHost))
        {
            pingTargetHost = inputHost;
        }

        Console.Clear();

        string[] logo = new string[]
        {
            "██████╗ ██████╗  █████╗ ███╗   ██╗████████╗███████╗ ██████╗███████╗██████╗ ",
            "██╔══██╗██╔══██╗██╔══██╗████╗  ██║╚══██╔══╝██╔════╝██╔════╝██╔════╝██╔══██╗",
            "██████╔╝██████╔╝███████║██╔██╗ ██║   ██║   █████╗  ██║     █████╗  ██████╔╝",
            "██╔═══╝ ██╔══██╗██╔══██║██║╚██╗██║   ██║   ██╔══╝  ██║     ██╔══╝  ██╔══██╗",
            "██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ███████╗╚██████╗███████╗██║  ██║",
            "╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═════╝ ╚═════╝╚══════╝╚═╝  ╚═╝"
        };

        int windowHeight = Console.WindowHeight;
        int contentHeight = 4;
        int startTop = Math.Max(0, (windowHeight - contentHeight) / 2);

        Console.SetCursorPosition(0, startTop);
        CenterText("Loading...");
        string divider = "------------------------------------";
        CenterText(divider);

        int barTop = Console.CursorTop;
        int totalBlocks = 20;
        string sampleBarText = $"Progress: [{new string('|', totalBlocks)}] 100%";
        int barLeft = Math.Max(0, (Console.WindowWidth - sampleBarText.Length) / 2);

        Console.SetCursorPosition(0, barTop + 1);
        CenterText(divider);

        for (int percent = 0; percent <= 100; percent++)
        {
            int currentBlocks = (percent * totalBlocks) / 100;
            string filledBar = new string('|', currentBlocks);
            string emptyBar = new string(' ', totalBlocks - currentBlocks);

            Console.SetCursorPosition(barLeft, barTop);
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("Progress: [");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write(filledBar);
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"{emptyBar}] {percent}%");

            Thread.Sleep(15);
        }

        Console.SetCursorPosition(0, 0);
        foreach (string line in logo)
        {
            CenterText(line);
        }

        var activeInterface = GetRealActiveNetworkInterface();

        if (activeInterface == null)
        {
            Console.SetCursorPosition(0, barTop + 3);
            CenterText("Ошибка: Нет подключения к интернету!");
            return;
        }

        var devices = CaptureDeviceList.Instance;
        var activeDevice = devices.FirstOrDefault(d =>
            d.MacAddress?.ToString() == activeInterface.GetPhysicalAddress().ToString() ||
            d.Name.Contains(activeInterface.Id));

        if (activeDevice == null)
        {
            Console.SetCursorPosition(0, barTop + 3);
            CenterText("Ошибка: Не удалось привязать SharpPcap!");
            return;
        }

        string connectionType = GetConnectionType(activeInterface.NetworkInterfaceType);

        Console.SetCursorPosition(0, barTop + 3);
        CenterText($"[ Подключение: {connectionType} | {activeInterface.Name} ]");
        CenterText($"[ Ping target: {pingTargetHost} ]");
        CenterText("Status: SNIFFING TRAFFIC (Press Enter to stop)");
        Console.WriteLine("\n" + new string('=', Console.WindowWidth));

        Thread pingThread = new Thread(PingWorker);
        pingThread.IsBackground = true;
        pingThread.Start();

        activeDevice.OnPacketArrival += OnPacketArrival;
        activeDevice.Open(DeviceModes.Promiscuous, 1000);
        activeDevice.StartCapture();

        Console.ReadLine();

        keepPinging = false;
        activeDevice.StopCapture();
        activeDevice.Close();
        Console.WriteLine("\nЗахват трафика остановлен.");
    }

    private static void PingWorker()
    {
        using (Ping pingSender = new Ping())
        {
            while (keepPinging)
            {
                try
                {
                    PingReply reply = pingSender.Send(pingTargetHost, 1000);
                    if (reply.Status == IPStatus.Success)
                    {
                        currentPingMs = reply.RoundtripTime;
                    }
                    else
                    {
                        currentPingMs = -1;
                    }
                }
                catch
                {
                    currentPingMs = -1;
                }

                Thread.Sleep(1000);
            }
        }
    }

    private static bool IsAdministrator()
    {
        var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static NetworkInterface GetRealActiveNetworkInterface()
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0);
            socket.Connect("8.8.8.8", 65530);
            var localIp = (socket.LocalEndPoint as System.Net.IPEndPoint)?.Address;

            if (localIp != null)
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    var props = ni.GetIPProperties();
                    if (props.UnicastAddresses.Any(u => u.Address.Equals(localIp)))
                    {
                        return ni;
                    }
                }
            }
        }
        catch { }

        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(ni => ni.OperationalStatus == OperationalStatus.Up &&
                         ni.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                         ni.NetworkInterfaceType != NetworkInterfaceType.Tunnel &&
                         !ni.Description.Contains("Radmin", StringComparison.OrdinalIgnoreCase) &&
                         !ni.Description.Contains("Virtual", StringComparison.OrdinalIgnoreCase) &&
                         !ni.Description.Contains("VPN", StringComparison.OrdinalIgnoreCase) &&
                         !ni.Description.Contains("TAP", StringComparison.OrdinalIgnoreCase) &&
                         !ni.Description.Contains("VMware", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(ni => ni.GetIPProperties().GatewayAddresses.Count > 0)
            .FirstOrDefault();
    }

    private static string GetConnectionType(NetworkInterfaceType type)
    {
        return type switch
        {
            NetworkInterfaceType.Wireless80211 => "Беспроводное",
            NetworkInterfaceType.Ethernet => "Кабельное",
            _ => $"Другое ({type})"
        };
    }

    private static void OnPacketArrival(object sender, PacketCapture e)
    {
        var rawPacket = e.GetPacket();
        var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

        var ipPacket = packet.Extract<IPPacket>();

        if (ipPacket != null)
        {
            DateTime time = rawPacket.Timeval.Date;
            string srcIp = ipPacket.SourceAddress.ToString();
            string dstIp = ipPacket.DestinationAddress.ToString();
            string protocol = ipPacket.Protocol.ToString();

            int srcPort = 0;
            int dstPort = 0;

            var tcpPacket = packet.Extract<TcpPacket>();
            var udpPacket = packet.Extract<UdpPacket>();

            if (tcpPacket != null)
            {
                srcPort = tcpPacket.SourcePort;
                dstPort = tcpPacket.DestinationPort;
            }
            else if (udpPacket != null)
            {
                srcPort = udpPacket.SourcePort;
                dstPort = udpPacket.DestinationPort;
            }

            string appName = GetAppName(srcPort, dstPort);

            if (currentPingMs >= 0)
            {
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.Write($"[PING {currentPingMs,3}ms] ");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($"[PING  TIMEOUT] ");
            }

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"[{time:HH:mm:ss.fff}] ");

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write($"[{appName,-15}] ");

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"[{protocol,-4}] ");

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"{srcIp}:{srcPort} --> {dstIp}:{dstPort} ({rawPacket.Data.Length} bytes)");
        }
    }

    private static string GetAppName(int srcPort, int dstPort)
    {
        int pid = GetPidByPort(srcPort);
        if (pid == 0) pid = GetPidByPort(dstPort);

        if (pid > 0)
        {
            try
            {
                var proc = Process.GetProcessById(pid);
                return proc.ProcessName;
            }
            catch
            {
                return "System";
            }
        }

        return "System";
    }

    private static int GetPidByPort(int port)
    {
        if (port <= 0) return 0;

        try
        {
            var p = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c netstat -ano | findstr :{port}",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();

            var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 5 && int.TryParse(parts.Last(), out int pid))
                {
                    return pid;
                }
            }
        }
        catch { }

        return 0;
    }

    static void CenterText(string text)
    {
        int left = Math.Max(0, (Console.WindowWidth - text.Length) / 2);
        Console.SetCursorPosition(left, Console.CursorTop);
        Console.WriteLine(text);
    }
}