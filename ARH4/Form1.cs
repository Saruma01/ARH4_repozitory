using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Windows.Forms;
using System.Collections.Generic;

namespace ARH4
{
    public partial class Form1 : Form
    {
        private Socket socket;
        private byte[] buffer = new byte[65535];
        private bool isCapturing = false;

        public Form1()
        {
            InitializeComponent();
            LoadNetworkInterfaces();
        }

        private void LoadNetworkInterfaces()
        {
            cmbInterfaces.Items.Add("127.0.0.1");
            foreach (IPAddress ip in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                    cmbInterfaces.Items.Add(ip.ToString());
            }
            cmbInterfaces.SelectedIndex = 0;
        }

        private void btnStartStop_Click(object sender, EventArgs e)
        {
            if (!isCapturing)
            {
                StartCapture();
                btnStartStop.Text = "Stop";
            }
            else
            {
                StopCapture();
                btnStartStop.Text = "Start";
            }
            isCapturing = !isCapturing;
        }

        private void StartCapture()
        {
            try
            {
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                socket.Bind(new IPEndPoint(IPAddress.Parse(cmbInterfaces.Text), 0));
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                socket.IOControl(IOControlCode.ReceiveAll, new byte[] { 1, 0, 0, 0 }, null);
                socket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, OnReceive, null);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error starting capture: {ex.Message}");
            }
        }

        private void OnReceive(IAsyncResult ar)
        {
            try
            {
                int received = socket.EndReceive(ar);
                if (received > 0)
                {
                    ParsePacket(buffer, received);
                    socket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, OnReceive, null);
                }
            }
            catch (ObjectDisposedException) { }
            catch (Exception ex)
            {
                Invoke((Action)(() => MessageBox.Show($"Receive error: {ex.Message}")));
            }
        }

        private void ParsePacket(byte[] data, int length)
        {
            Invoke((Action)(() =>
            {
                try
                {
                    IPHeader ipHeader = new IPHeader(data, length);
                    string connectionKey = $"{ipHeader.SourceAddress}-{ipHeader.DestinationAddress}";
                    string reverseKey = $"{ipHeader.DestinationAddress}-{ipHeader.SourceAddress}";

                    TreeNode connectionNode = FindOrCreateConnectionNode(connectionKey, reverseKey);
                    connectionNode.Nodes.Clear();

                    // Add IP details
                    TreeNode ipNode = connectionNode.Nodes.Add("IP");
                    ipNode.Nodes.Add($"Version: IPv{ipHeader.Version}");
                    ipNode.Nodes.Add($"Header Length: {ipHeader.HeaderLength} bytes");
                    ipNode.Nodes.Add($"Differentiated Services: 0x{ipHeader.DifferentiatedServices:X2}");
                    ipNode.Nodes.Add($"Total Length: {ipHeader.TotalLength}");
                    ipNode.Nodes.Add($"Identification: {ipHeader.Identification}");
                    ipNode.Nodes.Add($"Flags: {ipHeader.Flags}");
                    ipNode.Nodes.Add($"Fragment Offset: {ipHeader.FragmentOffset}");
                    ipNode.Nodes.Add($"TTL: {ipHeader.TTL}");
                    ipNode.Nodes.Add($"Protocol: {ipHeader.Protocol}");
                    ipNode.Nodes.Add($"Checksum: 0x{ipHeader.Checksum:X4}");
                    ipNode.Nodes.Add($"Source: {ipHeader.SourceAddress}");
                    ipNode.Nodes.Add($"Destination: {ipHeader.DestinationAddress}");

                    // Parse transport layer
                    if (ipHeader.Protocol == ProtocolType.Tcp && length >= ipHeader.HeaderLength + 20)
                    {
                        TCPHeader tcpHeader = new TCPHeader(data, ipHeader.HeaderLength);
                        AddTcpNode(connectionNode, tcpHeader);
                    }
                    else if (ipHeader.Protocol == ProtocolType.Udp && length >= ipHeader.HeaderLength + 8)
                    {
                        UDPHeader udpHeader = new UDPHeader(data, ipHeader.HeaderLength);
                        AddUdpNode(connectionNode, udpHeader);
                    }

                    connectionNode.Expand();
                    tvPackets.SelectedNode = connectionNode;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Parse error: {ex.Message}");
                }
            }));
        }

        private TreeNode FindOrCreateConnectionNode(string connectionKey, string reverseKey)
        {
            foreach (TreeNode node in tvPackets.Nodes)
            {
                if (node.Text == connectionKey || node.Text == reverseKey)
                    return node;
            }

            return tvPackets.Nodes.Add(connectionKey);
        }

        private void AddTcpNode(TreeNode parent, TCPHeader tcp)
        {
            TreeNode tcpNode = parent.Nodes.Add("TCP");
            tcpNode.Nodes.Add($"Source Port: {tcp.SourcePort}");
            tcpNode.Nodes.Add($"Destination Port: {tcp.DestinationPort}");
            tcpNode.Nodes.Add($"Sequence Number: {tcp.SequenceNumber}");
            tcpNode.Nodes.Add($"Acknowledgment Number: {tcp.AcknowledgementNumber}");
            tcpNode.Nodes.Add($"Header Length: {tcp.HeaderLength} bytes");
            tcpNode.Nodes.Add($"Flags: {tcp.Flags}");
            tcpNode.Nodes.Add($"Window Size: {tcp.WindowSize}");
            tcpNode.Nodes.Add($"Checksum: 0x{tcp.Checksum:X4}");
        }

        private void AddUdpNode(TreeNode parent, UDPHeader udp)
        {
            TreeNode udpNode = parent.Nodes.Add("UDP");
            udpNode.Nodes.Add($"Source Port: {udp.SourcePort}");
            udpNode.Nodes.Add($"Destination Port: {udp.DestinationPort}");
            udpNode.Nodes.Add($"Length: {udp.Length}");
            udpNode.Nodes.Add($"Checksum: 0x{udp.Checksum:X4}");
        }

        private void StopCapture()
        {
            if (socket != null)
            {
                socket.Close();
                socket = null;
            }
        }

        private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            StopCapture();
        }

        private void cmbInterfaces_SelectedIndexChanged(object sender, EventArgs e)
        {

        }
    }

    public class IPHeader
    {
        public byte Version { get; }
        public byte HeaderLength { get; }
        public byte DifferentiatedServices { get; }
        public ushort TotalLength { get; }
        public ushort Identification { get; }
        public string Flags { get; }
        public ushort FragmentOffset { get; }
        public byte TTL { get; }
        public ProtocolType Protocol { get; }
        public ushort Checksum { get; }
        public string SourceAddress { get; }
        public string DestinationAddress { get; }

        public IPHeader(byte[] buffer, int length)
        {
            Version = (byte)(buffer[0] >> 4);
            HeaderLength = (byte)((buffer[0] & 0x0F) * 4);
            DifferentiatedServices = buffer[1];
            TotalLength = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, 2));
            Identification = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, 4));

            ushort flagsOffset = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, 6));
            Flags = GetFlags(flagsOffset >> 13);
            FragmentOffset = (ushort)(flagsOffset & 0x1FFF);

            TTL = buffer[8];
            Protocol = (ProtocolType)buffer[9];
            Checksum = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, 10));
            SourceAddress = new IPAddress(BitConverter.ToUInt32(buffer, 12)).ToString();
            DestinationAddress = new IPAddress(BitConverter.ToUInt32(buffer, 16)).ToString();
        }

        private string GetFlags(int flags)
        {
            List<string> flagList = new List<string>();
            if ((flags & 0x01) != 0) flagList.Add("MF");
            if ((flags & 0x02) != 0) flagList.Add("DF");
            return flagList.Count > 0 ? string.Join(", ", flagList) : "None";
        }
    }

    public class TCPHeader
    {
        public ushort SourcePort { get; }
        public ushort DestinationPort { get; }
        public uint SequenceNumber { get; }
        public uint AcknowledgementNumber { get; }
        public byte HeaderLength { get; }
        public string Flags { get; }
        public ushort WindowSize { get; }
        public ushort Checksum { get; }

        public TCPHeader(byte[] buffer, int offset)
        {
            SourcePort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset));
            DestinationPort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset + 2));
            SequenceNumber = (uint)IPAddress.NetworkToHostOrder(BitConverter.ToInt32(buffer, offset + 4));
            AcknowledgementNumber = (uint)IPAddress.NetworkToHostOrder(BitConverter.ToInt32(buffer, offset + 8));

            byte dataOffset = buffer[offset + 12];
            HeaderLength = (byte)((dataOffset >> 4) * 4);

            Flags = GetTcpFlags(buffer[offset + 13]);
            WindowSize = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset + 14));
            Checksum = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset + 16));
        }

        private string GetTcpFlags(byte flags)
        {
            List<string> flagList = new List<string>();
            if ((flags & 0x01) != 0) flagList.Add("FIN");
            if ((flags & 0x02) != 0) flagList.Add("SYN");
            if ((flags & 0x04) != 0) flagList.Add("RST");
            if ((flags & 0x08) != 0) flagList.Add("PSH");
            if ((flags & 0x10) != 0) flagList.Add("ACK");
            if ((flags & 0x20) != 0) flagList.Add("URG");
            return flagList.Count > 0 ? string.Join(", ", flagList) : "None";
        }
    }

    public class UDPHeader
    {
        public ushort SourcePort { get; }
        public ushort DestinationPort { get; }
        public ushort Length { get; }
        public ushort Checksum { get; }

        public UDPHeader(byte[] buffer, int offset)
        {
            SourcePort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset));
            DestinationPort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset + 2));
            Length = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset + 4));
            Checksum = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset + 6));
        }
    }
}