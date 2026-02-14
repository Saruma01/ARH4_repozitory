using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Xml.Linq;

namespace ARH4
{
    public partial class Form1 : Form
    {
        //Raw socket - "сырой" сокет, работающий на сетевом уровне и позволяющий получать пакеты со всеми заголовками
        private Socket socket; // Сокет для захвата пакетов
        private byte[] buffer = new byte[65535]; // Буфер для хранения пакетов
        private bool isCapturing = false; // Флаг состояния захвата

        public Form1()
        {
            InitializeComponent();
            LoadNetworkInterfaces(); // Загрузка доступных сетевых интерфейсов
        }

        // Загрузка списка сетевых интерфейсов
        private void LoadNetworkInterfaces()
        {
            cmbInterfaces.Items.Add("127.0.0.1"); // Добавляем localhost
            foreach (IPAddress ip in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork) // Только IPv4 адреса
                    cmbInterfaces.Items.Add(ip.ToString());
            }
            cmbInterfaces.SelectedIndex = 0; // Выбираем первый интерфейс по умолчанию
        }

        // Обработчик кнопки Start/Stop
        private void btnStartStop_Click(object sender, EventArgs e)
        {
            if (!isCapturing)
            {
                StartCapture(); // Запуск захвата
                btnStartStop.Text = "Stop";
            }
            else
            {
                StopCapture(); // Остановка захвата
                btnStartStop.Text = "Start";
            }
            isCapturing = !isCapturing; // Переключаем состояние
        }

        // Запуск захвата пакетов
        private void StartCapture()
        {
            try
            {
                // Создаем raw-сокет для захвата IP-пакетов
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                // Привязываем сокет к выбранному интерфейсу (порт 0 - любой)
                socket.Bind(new IPEndPoint(IPAddress.Parse(cmbInterfaces.Text), 0));
                // Включаем заголовки IP-пакетов
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                socket.IOControl(IOControlCode.ReceiveAll, new byte[] { 1, 0, 0, 0 }, null);
                // Начинаем асинхронный прием данных
                socket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, OnReceive, null);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error starting capture: {ex.Message}");
            }
        }

        // Обработчик получения данных
        private void OnReceive(IAsyncResult ar)
        {
            try
            {
                var received = socket.EndReceive(ar); // Завершаем прием
                if (received > 0)
                {
                    ParsePacket(buffer, received); // Анализируем полученный пакет
                    // Продолжаем прием
                    socket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, OnReceive, null);
                }
            }
            catch (ObjectDisposedException) { } // Игнорируем, если сокет закрыт
            catch (Exception ex)
            {
                Invoke((Action)(() => MessageBox.Show($"Receive error: {ex.Message}")));
            }
        }

        // Анализ IP-пакета
        private void ParsePacket(byte[] data, int length)
        {
            // Invoke используется для безопасного обращения к элементам UI из другого потока
            Invoke((Action)(() =>
            {
                try
                {
                    IPHeader ipHeader = new IPHeader(data, length); // Парсим IP-заголовок
                    string connectionKey = $"{ipHeader.SourceAddress}-{ipHeader.DestinationAddress}"; // Создаем ключи для идентификации соединения в обоих направлениях
                    string reverseKey = $"{ipHeader.DestinationAddress}-{ipHeader.SourceAddress}";

                    // Находим или создаем узел для этого соединения
                    TreeNode connectionNode = FindOrCreateConnectionNode(connectionKey, reverseKey);
                    connectionNode.Nodes.Clear();

                    // Добавляем детали IP-заголовка
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

                    // Анализ транспортного уровня
                    if (ipHeader.Protocol == ProtocolType.Tcp && length >= ipHeader.HeaderLength + 20)
                    {
                        TCPHeader tcpHeader = new TCPHeader(data, ipHeader.HeaderLength);
                        AddTcpNode(connectionNode, tcpHeader);

                        // Проверка на DNS поверх TCP (порт 53)
                        if ((tcpHeader.SourcePort == 53 || tcpHeader.DestinationPort == 53) &&
                            length >= ipHeader.HeaderLength + tcpHeader.HeaderLength + 12)
                        {
                            DNSHeader dnsHeader = new DNSHeader(data, ipHeader.HeaderLength + tcpHeader.HeaderLength);
                            AddDnsNode(connectionNode, dnsHeader, data, ipHeader.HeaderLength + tcpHeader.HeaderLength);
                        }
                    }
                    else if (ipHeader.Protocol == ProtocolType.Udp && length >= ipHeader.HeaderLength + 8)
                    {
                        // Анализ UDP
                        UDPHeader udpHeader = new UDPHeader(data, ipHeader.HeaderLength);
                        AddUdpNode(connectionNode, udpHeader);

                        // Проверка на DNS поверх UDP (порт 53)
                        if ((udpHeader.SourcePort == 53 || udpHeader.DestinationPort == 53) &&
                            length >= ipHeader.HeaderLength + 8 + 12)
                        {
                            DNSHeader dnsHeader = new DNSHeader(data, ipHeader.HeaderLength + 8);
                            AddDnsNode(connectionNode, dnsHeader, data, ipHeader.HeaderLength + 8);
                        }
                    }

                    connectionNode.Expand(); // Разворачиваем узел
                    tvPackets.SelectedNode = connectionNode; // Выделяем узел
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Parse error: {ex.Message}");
                }
            }));
        }

        // Добавление DNS-узла
        private void AddDnsNode(TreeNode parent, DNSHeader dns, byte[] data, int offset)
        {
            TreeNode dnsNode = parent.Nodes.Add("DNS");
            dnsNode.Nodes.Add($"Transaction ID: 0x{dns.TransactionID:X4}");
            dnsNode.Nodes.Add($"Flags: 0x{dns.Flags:X4}");
            dnsNode.Nodes.Add($"Questions: {dns.Questions}");
            dnsNode.Nodes.Add($"Answer RRs: {dns.AnswerRRs}");
            dnsNode.Nodes.Add($"Authority RRs: {dns.AuthorityRRs}");
            dnsNode.Nodes.Add($"Additional RRs: {dns.AdditionalRRs}");

            // Парсинг вопросов
            if (dns.Questions > 0)
            {
                TreeNode questionsNode = dnsNode.Nodes.Add("Questions");
                int currentOffset = offset + 12;
                for (int i = 0; i < dns.Questions; i++)
                {
                    string name = ReadDnsName(data, ref currentOffset);
                    ushort type = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, currentOffset));
                    currentOffset += 2;
                    ushort qclass = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, currentOffset));
                    currentOffset += 2;

                    TreeNode questionNode = questionsNode.Nodes.Add($"Question {i + 1}");
                    questionNode.Nodes.Add($"Name: {name}");
                    questionNode.Nodes.Add($"Type: {GetDnsType(type)}");
                    questionNode.Nodes.Add($"Class: {GetDnsClass(qclass)}");
                }
            }

            // Парсинг ответов
            if (dns.AnswerRRs > 0)
            {
                TreeNode answersNode = dnsNode.Nodes.Add("Answers");
                ParseDnsResourceRecords(data, ref offset, dns.AnswerRRs, answersNode);
            }

            // Парсинг авторитетных записей
            if (dns.AuthorityRRs > 0)
            {
                TreeNode authNode = dnsNode.Nodes.Add("Authority Records");
                ParseDnsResourceRecords(data, ref offset, dns.AuthorityRRs, authNode);
            }

            // Парсинг дополнительных записей
            if (dns.AdditionalRRs > 0)
            {
                TreeNode addNode = dnsNode.Nodes.Add("Additional Records");
                ParseDnsResourceRecords(data, ref offset, dns.AdditionalRRs, addNode);
            }
        }

        // Парсинг DNS resource records
        private void ParseDnsResourceRecords(byte[] data, ref int offset, int count, TreeNode parentNode)
        {
            for (int i = 0; i < count; i++)
            {
                string name = ReadDnsName(data, ref offset);
                ushort type = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, offset));
                offset += 2;
                ushort rrclass = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, offset));
                offset += 2;
                uint ttl = (uint)IPAddress.NetworkToHostOrder(BitConverter.ToInt32(data, offset));
                offset += 4;
                ushort rdlength = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, offset));
                offset += 2;
                byte[] rdata = new byte[rdlength];
                Array.Copy(data, offset, rdata, 0, rdlength);
                offset += rdlength;

                TreeNode rrNode = parentNode.Nodes.Add($"Record {i + 1}");
                rrNode.Nodes.Add($"Name: {name}");
                rrNode.Nodes.Add($"Type: {GetDnsType(type)}");
                rrNode.Nodes.Add($"Class: {GetDnsClass(rrclass)}");
                rrNode.Nodes.Add($"TTL: {ttl}");
                rrNode.Nodes.Add($"Data Length: {rdlength}");

                // Обработка конкретных типов записей
                switch (type)
                {
                    case 1: // A record
                        if (rdlength == 4)
                        {
                            rrNode.Nodes.Add($"Address: {new IPAddress(rdata).ToString()}");
                        }
                        break;
                    case 5: // CNAME record
                        rrNode.Nodes.Add($"Canonical Name: {ReadDnsName(data, ref offset, rdata)}");
                        break;
                    case 28: // AAAA record
                        if (rdlength == 16)
                        {
                            rrNode.Nodes.Add($"IPv6 Address: {new IPAddress(rdata).ToString()}");
                        }
                        break;
                    case 15: // MX record
                        if (rdlength >= 2)
                        {
                            ushort preference = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(rdata, 0));
                            string mxName = ReadDnsName(data, ref offset, rdata, 2);
                            rrNode.Nodes.Add($"Preference: {preference}");
                            rrNode.Nodes.Add($"Mail Exchange: {mxName}");
                        }
                        break;
                    case 2: // NS record
                        rrNode.Nodes.Add($"Name Server: {ReadDnsName(data, ref offset, rdata)}");
                        break;
                    case 16: // TXT record
                        if (rdlength > 0)
                        {
                            string txt = Encoding.ASCII.GetString(rdata);
                            rrNode.Nodes.Add($"Text: {txt}");
                        }
                        break;
                }
            }
        }

        // Чтение DNS-имени с учетом компрессии
        private string ReadDnsName(byte[] data, ref int offset, byte[] rdata = null, int rdataOffset = 0)
        {
            StringBuilder name = new StringBuilder();
            int pos = (rdata != null) ? rdataOffset : offset;
            byte[] workingData = (rdata != null) ? rdata : data;
            bool isCompressed = false;
            int originalOffset = offset;

            while (true)
            {
                if (pos >= workingData.Length) break;

                byte len = workingData[pos++];
                if (len == 0) break;

                // Проверка на компрессию DNS (первые два бита установлены)
                if ((len & 0xC0) == 0xC0)
                {
                    if (!isCompressed)
                    {
                        if (rdata == null)
                        {
                            offset = pos + 1; // Обновляем offset только для первого указателя компрессии
                        }
                        isCompressed = true;
                    }

                    // Получаем offset из указателя компрессии
                    ushort pointer = (ushort)(((len & 0x3F) << 8) | workingData[pos++]);
                    byte[] savedData = workingData;
                    int savedPos = pos;

                    // Переходим по указателю
                    workingData = data;
                    pos = pointer;

                    // Рекурсивный вызов для обработки сжатого имени
                    string part = ReadDnsName(data, ref pos);
                    name.Append(part);

                    // Восстанавливаем оригинальный контекст
                    workingData = savedData;
                    pos = savedPos;
                    break;
                }
                else
                {
                    if (pos + len > workingData.Length) break;
                    string label = Encoding.ASCII.GetString(workingData, pos, len);
                    name.Append(label);
                    name.Append('.');
                    pos += len;
                }
            }

            if (!isCompressed && rdata == null)
            {
                offset = pos;
            }

            // Удаляем завершающую точку, если есть
            if (name.Length > 0 && name[name.Length - 1] == '.')
            {
                name.Length--;
            }

            return name.ToString();
        }

        // Получение строкового представления типа DNS-записи
        private string GetDnsType(ushort type)
        {
            switch (type)
            {
                case 1: return "A (Host Address)";
                case 2: return "NS (Name Server)";
                case 5: return "CNAME (Canonical Name)";
                case 6: return "SOA (Start of Authority)";
                case 12: return "PTR (Pointer)";
                case 15: return "MX (Mail Exchange)";
                case 16: return "TXT (Text)";
                case 28: return "AAAA (IPv6 Address)";
                case 33: return "SRV (Service Location)";
                default: return $"Unknown ({type})";
            }
        }

        // Получение строкового представления класса DNS-записи
        private string GetDnsClass(ushort qclass)
        {
            switch (qclass)
            {
                case 1: return "IN (Internet)";
                case 2: return "CS (CSNET)";
                case 3: return "CH (CHAOS)";
                case 4: return "HS (Hesiod)";
                default: return $"Unknown ({qclass})";
            }
        }

        // Поиск или создание узла соединения
        private TreeNode FindOrCreateConnectionNode(string connectionKey, string reverseKey)
        {
            foreach (TreeNode node in tvPackets.Nodes)
            {
                if (node.Text == connectionKey || node.Text == reverseKey)
                    return node;
            }

            return tvPackets.Nodes.Add(connectionKey);
        }

        // Добавление TCP-узла
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

        // Добавление UDP-узла
        private void AddUdpNode(TreeNode parent, UDPHeader udp)
        {
            TreeNode udpNode = parent.Nodes.Add("UDP");
            udpNode.Nodes.Add($"Source Port: {udp.SourcePort}");
            udpNode.Nodes.Add($"Destination Port: {udp.DestinationPort}");
            udpNode.Nodes.Add($"Length: {udp.Length}");
            udpNode.Nodes.Add($"Checksum: 0x{udp.Checksum:X4}");
        }

        // Остановка захвата пакетов
        private void StopCapture()
        {
            if (socket != null)
            {
                socket.Close();
                socket = null;
            }
        }

        // Обработчик закрытия формы
        private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            StopCapture();
        }

        private void cmbInterfaces_SelectedIndexChanged(object sender, EventArgs e)
        {
            // Обработчик изменения выбранного интерфейса
        }
    }

    // Класс для представления IP-заголовка
    public class IPHeader
    {
        public byte Version { get; } // Версия IP (4 или 6)
        public byte HeaderLength { get; } // Длина заголовка в 32-битных словах
        public byte DifferentiatedServices { get; } // Поле DSCP/ECN
        public ushort TotalLength { get; } // Общая длина пакета
        public ushort Identification { get; } // Идентификатор пакета
        public string Flags { get; } // Флаги (DF, MF)
        public ushort FragmentOffset { get; } // Смещение фрагмента
        public byte TTL { get; } // Время жизни пакета
        public ProtocolType Protocol { get; } // Протокол верхнего уровня (TCP, UDP и др.)
        public ushort Checksum { get; } // Контрольная сумма
        public string SourceAddress { get; } // IP-адрес отправителя
        public string DestinationAddress { get; } // IP-адрес получателя

        public IPHeader(byte[] buffer, int length)
        {
            Version = (byte)(buffer[0] >> 4); // Первые 4 бита - версия
            HeaderLength = (byte)((buffer[0] & 0x0F) * 4); // Вторые 4 бита * 4 = длина в байтах
            DifferentiatedServices = buffer[1]; // DSCP/ECN
            TotalLength = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, 2));
            Identification = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, 4));

            ushort flagsOffset = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, 6));
            Flags = GetFlags(flagsOffset >> 13); // Первые 3 бита - флаги
            FragmentOffset = (ushort)(flagsOffset & 0x1FFF); // Оставшиеся 13 бит - смещение

            TTL = buffer[8];
            Protocol = (ProtocolType)buffer[9];
            Checksum = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, 10));
            SourceAddress = new IPAddress(BitConverter.ToUInt32(buffer, 12)).ToString();
            DestinationAddress = new IPAddress(BitConverter.ToUInt32(buffer, 16)).ToString();
        }

        private string GetFlags(int flags)
        {
            List<string> flagList = new List<string>();
            if ((flags & 0x01) != 0) flagList.Add("MF"); // More Fragments
            if ((flags & 0x02) != 0) flagList.Add("DF"); // Don't Fragment
            return flagList.Count > 0 ? string.Join(", ", flagList) : "None";
        }
    }

    // Класс для представления TCP-заголовка
    public class TCPHeader
    {
        public ushort SourcePort { get; }
        public ushort DestinationPort { get; }
        public uint SequenceNumber { get; }
        public uint AcknowledgementNumber { get; }
        public byte HeaderLength { get; } // Длина заголовка в 32-битных словах
        public string Flags { get; } // Флаги (SYN, ACK и др.)
        public ushort WindowSize { get; } // Размер окна
        public ushort Checksum { get; } // Контрольная сумма

        public TCPHeader(byte[] buffer, int offset)
        {
            SourcePort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset));
            DestinationPort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset + 2));
            SequenceNumber = (uint)IPAddress.NetworkToHostOrder(BitConverter.ToInt32(buffer, offset + 4));
            AcknowledgementNumber = (uint)IPAddress.NetworkToHostOrder(BitConverter.ToInt32(buffer, offset + 8));

            byte dataOffset = buffer[offset + 12];
            HeaderLength = (byte)((dataOffset >> 4) * 4); // Верхние 4 бита * 4 = длина в байтах

            Flags = GetTcpFlags(buffer[offset + 13]);
            WindowSize = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset + 14));
            Checksum = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset + 16));
        }

        private string GetTcpFlags(byte flags)
        {
            List<string> flagList = new List<string>();
            if ((flags & 0x01) != 0) flagList.Add("FIN"); // Флаг завершения
            if ((flags & 0x02) != 0) flagList.Add("SYN"); // Синхронизация
            if ((flags & 0x04) != 0) flagList.Add("RST"); // Сброс
            if ((flags & 0x08) != 0) flagList.Add("PSH"); // Push
            if ((flags & 0x10) != 0) flagList.Add("ACK"); // Подтверждение
            if ((flags & 0x20) != 0) flagList.Add("URG"); // Срочные данные
            return flagList.Count > 0 ? string.Join(", ", flagList) : "None";
        }
    }

    // Класс для представления UDP-заголовка
    public class UDPHeader
    {
        public ushort SourcePort { get; }
        public ushort DestinationPort { get; }
        public ushort Length { get; } // Длина заголовка + данных
        public ushort Checksum { get; } // Контрольная сумма

        public UDPHeader(byte[] buffer, int offset)
        {
            SourcePort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset));
            DestinationPort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset + 2));
            Length = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset + 4));
            Checksum = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset + 6));
        }
    }

    // Класс для представления DNS-заголовка
    public class DNSHeader
    {
        public ushort TransactionID { get; } // Идентификатор транзакции
        public ushort Flags { get; } // Флаги запроса/ответа
        public ushort Questions { get; } // Количество вопросов
        public ushort AnswerRRs { get; } // Количество ответов
        public ushort AuthorityRRs { get; } // Количество авторитетных записей
        public ushort AdditionalRRs { get; } // Количество дополнительных записей

        public DNSHeader(byte[] buffer, int offset)
        {
            TransactionID = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset));
            Flags = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset + 2));
            Questions = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset + 4));
            AnswerRRs = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset + 6));
            AuthorityRRs = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset + 8));
            AdditionalRRs = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, offset + 10));
        }
    }
}