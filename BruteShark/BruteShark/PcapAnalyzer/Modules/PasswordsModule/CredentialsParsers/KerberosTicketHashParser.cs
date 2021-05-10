﻿using System;
using System.Collections.Generic;
using System.Text;

namespace PcapAnalyzer
{
    class KerberosTicketHashParser : IPasswordParser
    {
        public NetworkLayerObject Parse(UdpPacket udpPacket) => 
            this.GetKerberosTicketsHash(udpPacket.SourceIp, udpPacket.DestinationIp, "UDP", udpPacket.Data);

        public NetworkLayerObject Parse(TcpPacket tcpPacket) => 
            this.GetKerberosTicketsHash(tcpPacket.SourceIp, tcpPacket.DestinationIp, "TCP", tcpPacket.Data);

        public NetworkLayerObject Parse(TcpSession tcpSession) => null;

        private NetworkLayerObject GetKerberosTicketsHash(string source, string destination, string protocol, byte[] data)
        {
            var kerberosPacket = KerberosPacketParser.GetKerberosPacket(data, protocol);

            if (kerberosPacket is null)
            {
                return null;
            }

            // TODO: use enum for hashes types
            if (kerberosPacket is KerberosTgsRepPacket)
            {
                var kerberosTgsRepPacket = kerberosPacket as KerberosTgsRepPacket;

                if (kerberosTgsRepPacket.Ticket.EncrytedPart.Etype == 23 || kerberosTgsRepPacket.Ticket.EncrytedPart.Etype == 18 || kerberosTgsRepPacket.Ticket.EncrytedPart.Etype == 17)
                {
                    return new KerberosTgsRepHash()
                    {
                        Source = source,
                        Destination = destination,
                        Realm = kerberosTgsRepPacket.Ticket.Realm,
                        Etype = kerberosTgsRepPacket.Ticket.EncrytedPart.Etype,
                        Username = kerberosTgsRepPacket.Cname.Name,
                        ServiceName = kerberosTgsRepPacket.Ticket.Sname.Name,
                        Hash = NtlmsspHashParser.ByteArrayToHexString(kerberosTgsRepPacket.Ticket.EncrytedPart.Cipher),
                        Protocol = protocol,
                        HashType = $"Kerberos V5 TGS-REP etype {kerberosTgsRepPacket.Ticket.EncrytedPart.Etype}"
                    };
                }
            }
            else if (kerberosPacket is KerberosAsRepPacket)
            {
                var kerberosAsRepPacket = kerberosPacket as KerberosAsRepPacket;

                if (kerberosAsRepPacket.Ticket.EncrytedPart.Etype == 23 || kerberosAsRepPacket.Ticket.EncrytedPart.Etype == 18)
                {
                    return new KerberosAsRepHash()
                    {
                        Source = source,
                        Destination = destination,
                        Realm = kerberosAsRepPacket.Ticket.Realm,
                        Etype = kerberosAsRepPacket.Ticket.EncrytedPart.Etype,
                        Username = kerberosAsRepPacket.Cname.Name,
                        ServiceName = kerberosAsRepPacket.Ticket.Sname.Name,
                        Hash = NtlmsspHashParser.ByteArrayToHexString(kerberosAsRepPacket.Ticket.EncrytedPart.Cipher),
                        Protocol = protocol,
                        HashType = $"Kerberos V5 AS-REP etype {kerberosAsRepPacket.Ticket.EncrytedPart.Etype}"
                    };
                }
            }

            return null;
        }
    }
}
