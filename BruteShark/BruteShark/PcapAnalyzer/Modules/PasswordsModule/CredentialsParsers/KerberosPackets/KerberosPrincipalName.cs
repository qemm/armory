﻿using Asn1;
using System;
using System.Collections.Generic;
using System.Text;

namespace PcapAnalyzer
{
    // PrincipalName::= SEQUENCE {
    //      name-type[0]    NAME-TYPE,
    //      name-string[1]  SEQUENCE OF GeneralString
    // }
    //
    // NAME-TYPE::= INTEGER {
    //      KRB5_NT_UNKNOWN(0),	-- Name type not known
    //      
    //      KRB5_NT_PRINCIPAL(1),	-- Just the name of the principal as in
    //      KRB5_NT_SRV_INST(2),	-- Service and other unique instance(krbtgt)
    //      KRB5_NT_SRV_HST(3),	-- Service with host name as instance
    //      KRB5_NT_SRV_XHST(4),	-- Service with host as remaining components
    //      KRB5_NT_UID(5),		-- Unique ID
    //      KRB5_NT_X500_PRINCIPAL(6), -- PKINIT
    //      KRB5_NT_SMTP_NAME(7),	-- Name in form of SMTP email name
    //      KRB5_NT_ENTERPRISE_PRINCIPAL(10), -- Windows 2000 UPN
    //      KRB5_NT_WELLKNOWN(11),	-- Wellknown
    //      KRB5_NT_ENT_PRINCIPAL_AND_ID(-130), -- Windows 2000 UPN and SID
    //      KRB5_NT_MS_PRINCIPAL(-128), -- NT 4 style name
    //      KRB5_NT_MS_PRINCIPAL_AND_ID(-129), -- NT style name and SID
    //      KRB5_NT_NTLM(-1200) -- NTLM name, realm is domain
    // }
    public class KerberosPrincipalName
    {
        const int KRB5_NT_PRINCIPAL = 1;
        const int KRB5_NT_SRV_INST =  2;

        public int NameType { get; private set; }
        public List<string> NameString { get; private set; }
        public string Name
        {
            get
            {
                if (this.NameType == KRB5_NT_PRINCIPAL && this.NameString.Count >= 1)
                {
                    return this.NameString[0];
                }
                else if (this.NameType == KRB5_NT_SRV_INST && this.NameString.Count >= 2)
                {
                    return this.NameString[0] + "/" + this.NameString[1];
                }

                return null;
            }
        }

        public KerberosPrincipalName(AsnElt principalNameData)
        {
            this.NameString = new List<string>();

            foreach (AsnElt s in principalNameData.Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        this.NameType = Convert.ToInt32(s.Sub[0].GetInteger());
                        break;
                    case 1:
                        foreach (AsnElt i in s.Sub[0].Sub)
                        {
                            this.NameString.Add(Encoding.ASCII.GetString(i.GetOctetString()));
                        }
                        break;
                }
            }
        }
    }
}
