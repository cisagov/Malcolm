# <a name="APIExamples"></a>Examples

Some security-related API examples:

* [Protocols](#Protocols)
* [Software](#Software)
* [User agent](#UserAgent)
* [External traffic (outbound/inbound)](#ExternalTraffic)
* [Cross-segment traffic](#CrossSegmentTraffic)
* [Plaintext password](#PlaintextPassword)
* [Insecure/outdated protocols](#InsecureProtocol)
* [Notice categories](#NoticeCategories)
* [Severity tags](#SeverityTags)

## <a name="Protocols"></a>Protocols

```
/mapi/agg/network.type,network.transport,network.protocol,network.protocol_version
```

```json
{
    "fields": [
        "network.type",
        "network.transport",
        "network.protocol",
        "network.protocol_version"
    ],
    "filter": null,
    "range": [
        1970,
        1643067256
    ],
    "urls": [
        "/dashboards/app/dashboards#/view/abdd7550-2c7c-40dc-947e-f6d186a158c4?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:'1970-01-01T00:32:50Z',to:now))"
    ],
    "values": {
        "buckets": [
            {
                "doc_count": 442240,
                "key": "ipv4",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 279538,
                            "key": "udp",
                            "values": {
                                "buckets": [
                                    {
                                        "doc_count": 266527,
                                        "key": "bacnet",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 12365,
                                        "key": "dns",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 78,
                                        "key": "dhcp",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 44,
                                        "key": "ntp",
                                        "values": {
                                            "buckets": [
                                                {
                                                    "doc_count": 22,
                                                    "key": "4"
                                                }
                                            ],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 3,
                                        "key": "enip",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 2,
                                        "key": "krb",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 1,
                                        "key": "syslog",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    }
                                ],
                                "doc_count_error_upper_bound": 0,
                                "sum_other_doc_count": 0
                            }
                        },
                        {
                            "doc_count": 30824,
                            "key": "tcp",
                            "values": {
                                "buckets": [
                                    {
                                        "doc_count": 7097,
                                        "key": "smb",
                                        "values": {
                                            "buckets": [
                                                {
                                                    "doc_count": 4244,
                                                    "key": "1"
                                                },
                                                {
                                                    "doc_count": 1438,
                                                    "key": "2"
                                                }
                                            ],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 1792,
                                        "key": "http",
                                        "values": {
                                            "buckets": [
                                                {
                                                    "doc_count": 829,
                                                    "key": "1.0"
                                                },
                                                {
                                                    "doc_count": 230,
                                                    "key": "1.1"
                                                }
                                            ],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 1280,
                                        "key": "dce_rpc",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 857,
                                        "key": "s7comm",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 426,
                                        "key": "ntlm",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 378,
                                        "key": "gssapi",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 146,
                                        "key": "tds",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 125,
                                        "key": "ssl",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 91,
                                        "key": "tls",
                                        "values": {
                                            "buckets": [
                                                {
                                                    "doc_count": 48,
                                                    "key": "TLSv13"
                                                },
                                                {
                                                    "doc_count": 28,
                                                    "key": "TLSv12"
                                                }
                                            ],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 29,
                                        "key": "ssh",
                                        "values": {
                                            "buckets": [
                                                {
                                                    "doc_count": 18,
                                                    "key": "2"
                                                }
                                            ],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 26,
                                        "key": "modbus",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 17,
                                        "key": "iso_cotp",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 8,
                                        "key": "enip",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 6,
                                        "key": "rdp",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 4,
                                        "key": "ftp",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 4,
                                        "key": "krb",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 4,
                                        "key": "rfb",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 3,
                                        "key": "ldap",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    },
                                    {
                                        "doc_count": 2,
                                        "key": "telnet",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    }
                                ],
                                "doc_count_error_upper_bound": 0,
                                "sum_other_doc_count": 0
                            }
                        },
                        {
                            "doc_count": 848,
                            "key": "icmp",
                            "values": {
                                "buckets": [],
                                "doc_count_error_upper_bound": 0,
                                "sum_other_doc_count": 0
                            }
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 1573,
                "key": "ipv6",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 1486,
                            "key": "udp",
                            "values": {
                                "buckets": [
                                    {
                                        "doc_count": 1433,
                                        "key": "dns",
                                        "values": {
                                            "buckets": [],
                                            "doc_count_error_upper_bound": 0,
                                            "sum_other_doc_count": 0
                                        }
                                    }
                                ],
                                "doc_count_error_upper_bound": 0,
                                "sum_other_doc_count": 0
                            }
                        },
                        {
                            "doc_count": 80,
                            "key": "icmp",
                            "values": {
                                "buckets": [],
                                "doc_count_error_upper_bound": 0,
                                "sum_other_doc_count": 0
                            }
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            }
        ],
        "doc_count_error_upper_bound": 0,
        "sum_other_doc_count": 0
    }
}
```

## <a name="Software"></a>Software

```
/mapi/agg/zeek.software.name,zeek.software.unparsed_version
```

```json
{
    "fields": [
        "zeek.software.name",
        "zeek.software.unparsed_version"
    ],
    "filter": null,
    "range": [
        1970,
        1643067759
    ],
    "urls": [
        "/dashboards/app/dashboards#/view/87d990cc-9e0b-41e5-b8fe-b10ae1da0c85?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:'1970-01-01T00:32:50Z',to:now))"
    ],
    "values": {
        "buckets": [
            {
                "doc_count": 6,
                "key": "Chrome",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 2,
                            "key": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36"
                        },
                        {
                            "doc_count": 1,
                            "key": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36"
                        },
                        {
                            "doc_count": 1,
                            "key": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36"
                        },
                        {
                            "doc_count": 1,
                            "key": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36"
                        },
                        {
                            "doc_count": 1,
                            "key": "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.36 Safari/525.19"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 6,
                "key": "Nmap-SSH",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 3,
                            "key": "Nmap-SSH1-Hostkey"
                        },
                        {
                            "doc_count": 3,
                            "key": "Nmap-SSH2-Hostkey"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 5,
                "key": "MSIE",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 2,
                            "key": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
                        },
                        {
                            "doc_count": 1,
                            "key": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)"
                        },
                        {
                            "doc_count": 1,
                            "key": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)"
                        },
                        {
                            "doc_count": 1,
                            "key": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 4,
                "key": "Firefox",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 2,
                            "key": "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
                        },
                        {
                            "doc_count": 1,
                            "key": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:34.0) Gecko/20100101 Firefox/34.0"
                        },
                        {
                            "doc_count": 1,
                            "key": "Mozilla/5.0 (X11; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 3,
                "key": "ECS (sec",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 2,
                            "key": "ECS (sec/96EE)"
                        },
                        {
                            "doc_count": 1,
                            "key": "ECS (sec/97A6)"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 3,
                "key": "NmapNSE",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 3,
                            "key": "NmapNSE_1.0"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 2,
                "key": "<unknown browser>",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 2,
                            "key": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 2,
                "key": "Microsoft-Windows",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 2,
                            "key": "Microsoft-Windows/6.1 UPnP/1.0 Windows-Media-Player-DMS/12.0.7601.17514 DLNADOC/1.50"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 2,
                "key": "Microsoft-Windows-NT",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 2,
                            "key": "Microsoft-Windows-NT/5.1 UPnP/1.0 UPnP-Device-Host/1.0 Microsoft-HTTPAPI/2.0"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 2,
                "key": "SimpleHTTP",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 2,
                            "key": "SimpleHTTP/0.6 Python/2.7.17"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 2,
                "key": "Windows-Media-Player-DMS",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 2,
                            "key": "Windows-Media-Player-DMS/12.0.7601.17514"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 1,
                "key": "A-B WWW",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 1,
                            "key": "A-B WWW/0.1"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 1,
                "key": "CONF-CTR-NAE1",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 1,
                            "key": "CONF-CTR-NAE1"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 1,
                "key": "ClearSCADA",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 1,
                            "key": "ClearSCADA/6.72.4644.1"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 1,
                "key": "GoAhead-Webs",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 1,
                            "key": "GoAhead-Webs"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 1,
                "key": "MSFT",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 1,
                            "key": "MSFT 5.0"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 1,
                "key": "Microsoft-IIS",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 1,
                            "key": "Microsoft-IIS/7.5"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 1,
                "key": "Microsoft-WebDAV-MiniRedir",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 1,
                            "key": "Microsoft-WebDAV-MiniRedir/6.1.7601"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 1,
                "key": "Python-urllib",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 1,
                            "key": "Python-urllib/2.7"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 1,
                "key": "Schneider-WEB/V",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 1,
                            "key": "Schneider-WEB/V2.1.4"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 1,
                "key": "Version",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 1,
                            "key": "Version_1.0"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 1,
                "key": "nginx",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 1,
                            "key": "nginx"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 1,
                "key": "sublime-license-check",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 1,
                            "key": "sublime-license-check/3.0"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            }
        ],
        "doc_count_error_upper_bound": 0,
        "sum_other_doc_count": 0
    }
}
```

## <a name="UserAgent"></a>User agent

```
/mapi/agg/user_agent.original
```

```json
{
    "fields": [
        "user_agent.original"
    ],
    "filter": null,
    "range": [
        1970,
        1643067845
    ],
    "values": {
        "buckets": [
            {
                "doc_count": 230,
                "key": "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
            },
            {
                "doc_count": 142,
                "key": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"
            },
            {
                "doc_count": 114,
                "key": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)"
            },
            {
                "doc_count": 50,
                "key": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
            },
            {
                "doc_count": 48,
                "key": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36"
            },
            {
                "doc_count": 43,
                "key": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36"
            },
            {
                "doc_count": 33,
                "key": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:34.0) Gecko/20100101 Firefox/34.0"
            },
            {
                "doc_count": 17,
                "key": "Python-urllib/2.7"
            },
            {
                "doc_count": 12,
                "key": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
            },
            {
                "doc_count": 9,
                "key": "Microsoft-Windows/6.1 UPnP/1.0 Windows-Media-Player-DMS/12.0.7601.17514 DLNADOC/1.50"
            },
            {
                "doc_count": 9,
                "key": "Windows-Media-Player-DMS/12.0.7601.17514"
            },
            {
                "doc_count": 8,
                "key": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
            },
            {
                "doc_count": 5,
                "key": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36"
            },
            {
                "doc_count": 5,
                "key": "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.36 Safari/525.19"
            },
            {
                "doc_count": 3,
                "key": "Mozilla/5.0 (X11; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0"
            },
            {
                "doc_count": 2,
                "key": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36"
            },
            {
                "doc_count": 1,
                "key": "Microsoft-WebDAV-MiniRedir/6.1.7601"
            },
            {
                "doc_count": 1,
                "key": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)"
            },
            {
                "doc_count": 1,
                "key": "sublime-license-check/3.0"
            }
        ],
        "doc_count_error_upper_bound": 0,
        "sum_other_doc_count": 0
    }
}
```

## <a name="ExternalTraffic"></a>External traffic (outbound/inbound)

```
$ curl -k -u username -L -XPOST -H 'Content-Type: application/json' \
    'https://localhost/mapi/agg/network.protocol' \
    -d '{"filter":{"network.direction":["inbound","outbound"]}}'
```

```json
{
    "fields": [
        "network.protocol"
    ],
    "filter": {
        "network.direction": [
            "inbound",
            "outbound"
        ]
    },
    "range": [
        1970,
        1643068000
    ],
    "urls": [
        "/dashboards/app/dashboards#/view/abdd7550-2c7c-40dc-947e-f6d186a158c4?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:'1970-01-01T00:32:50Z',to:now))"
    ],
    "values": {
        "buckets": [
            {
                "doc_count": 202597,
                "key": "bacnet"
            },
            {
                "doc_count": 129,
                "key": "tls"
            },
            {
                "doc_count": 128,
                "key": "ssl"
            },
            {
                "doc_count": 33,
                "key": "http"
            },
            {
                "doc_count": 33,
                "key": "ntp"
            },
            {
                "doc_count": 20,
                "key": "dns"
            }
        ],
        "doc_count_error_upper_bound": 0,
        "sum_other_doc_count": 0
    }
}
```

## <a name="CrossSegmentTraffic"></a>Cross-segment traffic

```
$ curl -k -u username -L -XPOST -H 'Content-Type: application/json' \
    'https://localhost/mapi/agg/source.segment,destination.segment,network.protocol' \
    -d '{"filter":{"tags":"cross_segment"}}'
```

```json
{
    "fields": [
        "source.segment",
        "destination.segment",
        "network.protocol"
    ],
    "filter": {
        "tags": "cross_segment"
    },
    "range": [
        1970,
        1643068080
    ],
    "urls": [
        "/dashboards/app/dashboards#/view/abdd7550-2c7c-40dc-947e-f6d186a158c4?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:'1970-01-01T00:32:50Z',to:now))"
    ],
    "values": {
        "buckets": [
            {
                "doc_count": 6893,
                "key": "Corporate",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 6893,
                            "key": "OT",
                            "values": {
                                "buckets": [
                                    {
                                        "doc_count": 891,
                                        "key": "enip"
                                    },
                                    {
                                        "doc_count": 889,
                                        "key": "cip"
                                    },
                                    {
                                        "doc_count": 202,
                                        "key": "http"
                                    },
                                    {
                                        "doc_count": 146,
                                        "key": "modbus"
                                    },
                                    {
                                        "doc_count": 1,
                                        "key": "ftp"
                                    }
                                ],
                                "doc_count_error_upper_bound": 0,
                                "sum_other_doc_count": 0
                            }
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 189,
                "key": "OT",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 138,
                            "key": "Corporate",
                            "values": {
                                "buckets": [
                                    {
                                        "doc_count": 128,
                                        "key": "http"
                                    }
                                ],
                                "doc_count_error_upper_bound": 0,
                                "sum_other_doc_count": 0
                            }
                        },
                        {
                            "doc_count": 51,
                            "key": "DMZ",
                            "values": {
                                "buckets": [],
                                "doc_count_error_upper_bound": 0,
                                "sum_other_doc_count": 0
                            }
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 28,
                "key": "Battery Network",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 25,
                            "key": "Combined Cycle BOP",
                            "values": {
                                "buckets": [],
                                "doc_count_error_upper_bound": 0,
                                "sum_other_doc_count": 0
                            }
                        },
                        {
                            "doc_count": 3,
                            "key": "Solar Panel Network",
                            "values": {
                                "buckets": [],
                                "doc_count_error_upper_bound": 0,
                                "sum_other_doc_count": 0
                            }
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 20,
                "key": "Combined Cycle BOP",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 11,
                            "key": "Battery Network",
                            "values": {
                                "buckets": [],
                                "doc_count_error_upper_bound": 0,
                                "sum_other_doc_count": 0
                            }
                        },
                        {
                            "doc_count": 9,
                            "key": "Solar Panel Network",
                            "values": {
                                "buckets": [],
                                "doc_count_error_upper_bound": 0,
                                "sum_other_doc_count": 0
                            }
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 1,
                "key": "Solar Panel Network",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 1,
                            "key": "Combined Cycle BOP",
                            "values": {
                                "buckets": [],
                                "doc_count_error_upper_bound": 0,
                                "sum_other_doc_count": 0
                            }
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            }
        ],
        "doc_count_error_upper_bound": 0,
        "sum_other_doc_count": 0
    }
}
```

## <a name="PlaintextPassword"></a>Plaintext password

```
$ curl -k -u username -L -XPOST -H 'Content-Type: application/json' \
    'https://localhost/mapi/agg/network.protocol' \
    -d '{"filter":{"!related.password":null}}'
```

```json
{
    "fields": [
        "network.protocol"
    ],
    "filter": {
        "!related.password": null
    },
    "range": [
        1970,
        1643068162
    ],
    "urls": [
        "/dashboards/app/dashboards#/view/abdd7550-2c7c-40dc-947e-f6d186a158c4?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:'1970-01-01T00:32:50Z',to:now))"
    ],
    "values": {
        "buckets": [
            {
                "doc_count": 20,
                "key": "http"
            }
        ],
        "doc_count_error_upper_bound": 0,
        "sum_other_doc_count": 0
    }
}
```

## <a name="InsecureProtocol"></a>Insecure/outdated protocols

```
$ curl -k -u username -L -XPOST -H 'Content-Type: application/json' \
    'https://localhost/mapi/agg/network.protocol,network.protocol_version' \
    -d '{"filter":{"event.severity_tags":"Insecure or outdated protocol"}}'
```

```json
{
    "fields": [
        "network.protocol",
        "network.protocol_version"
    ],
    "filter": {
        "event.severity_tags": "Insecure or outdated protocol"
    },
    "range": [
        1970,
        1643068248
    ],
    "urls": [
        "/dashboards/app/dashboards#/view/abdd7550-2c7c-40dc-947e-f6d186a158c4?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:'1970-01-01T00:32:50Z',to:now))"
    ],
    "values": {
        "buckets": [
            {
                "doc_count": 4244,
                "key": "smb",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 4244,
                            "key": "1"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 2,
                "key": "ftp",
                "values": {
                    "buckets": [],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 2,
                "key": "rdp",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 1,
                            "key": "5.1"
                        },
                        {
                            "doc_count": 1,
                            "key": "5.2"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 2,
                "key": "telnet",
                "values": {
                    "buckets": [],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            }
        ],
        "doc_count_error_upper_bound": 0,
        "sum_other_doc_count": 0
    }
}
```

## <a name="NoticeCategories"></a>Notice categories

```
/mapi/agg/zeek.notice.category,zeek.notice.sub_category
```

```json
{
    "fields": [
        "zeek.notice.category",
        "zeek.notice.sub_category"
    ],
    "filter": null,
    "range": [
        1970,
        1643068300
    ],
    "urls": [
        "/dashboards/app/dashboards#/view/f1f09567-fc7f-450b-a341-19d2f2bb468b?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:'1970-01-01T00:32:50Z',to:now))",
        "/dashboards/app/dashboards#/view/95479950-41f2-11ea-88fa-7151df485405?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:'1970-01-01T00:32:50Z',to:now))"
    ],
    "values": {
        "buckets": [
            {
                "doc_count": 100,
                "key": "ATTACK",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 42,
                            "key": "Lateral_Movement_Extracted_File"
                        },
                        {
                            "doc_count": 30,
                            "key": "Lateral_Movement"
                        },
                        {
                            "doc_count": 17,
                            "key": "Discovery"
                        },
                        {
                            "doc_count": 5,
                            "key": "Execution"
                        },
                        {
                            "doc_count": 5,
                            "key": "Lateral_Movement_Multiple_Attempts"
                        },
                        {
                            "doc_count": 1,
                            "key": "Lateral_Movement_and_Execution"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 14,
                "key": "EternalSafety",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 11,
                            "key": "EternalSynergy"
                        },
                        {
                            "doc_count": 3,
                            "key": "ViolationPidMid"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 6,
                "key": "Scan",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 6,
                            "key": "Port_Scan"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            {
                "doc_count": 1,
                "key": "Ripple20",
                "values": {
                    "buckets": [
                        {
                            "doc_count": 1,
                            "key": "Treck_TCP_observed"
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            }
        ],
        "doc_count_error_upper_bound": 0,
        "sum_other_doc_count": 0
    }
}
```

## <a name="SeverityTags"></a>Severity tags

```
/mapi/agg/event.severity_tags
```

```json
{
    "fields": [
        "event.severity_tags"
    ],
    "filter": null,
    "range": [
        1970,
        1643068363
    ],
    "urls": [
        "/dashboards/app/dashboards#/view/d2dd0180-06b1-11ec-8c6b-353266ade330?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:'1970-01-01T00:32:50Z',to:now))",
        "/dashboards/app/dashboards#/view/95479950-41f2-11ea-88fa-7151df485405?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:'1970-01-01T00:32:50Z',to:now))"
    ],
    "values": {
        "buckets": [
            {
                "doc_count": 160180,
                "key": "Outbound traffic"
            },
            {
                "doc_count": 43059,
                "key": "Inbound traffic"
            },
            {
                "doc_count": 11091,
                "key": "Connection attempt rejected"
            },
            {
                "doc_count": 8967,
                "key": "Connection attempt, no reply"
            },
            {
                "doc_count": 7131,
                "key": "Cross-segment traffic"
            },
            {
                "doc_count": 4250,
                "key": "Insecure or outdated protocol"
            },
            {
                "doc_count": 2219,
                "key": "External traffic"
            },
            {
                "doc_count": 1985,
                "key": "Sensitive country"
            },
            {
                "doc_count": 760,
                "key": "Weird"
            },
            {
                "doc_count": 537,
                "key": "Connection aborted (originator)"
            },
            {
                "doc_count": 474,
                "key": "Connection aborted (responder)"
            },
            {
                "doc_count": 206,
                "key": "File transfer (high concern)"
            },
            {
                "doc_count": 100,
                "key": "MITRE ATT&CK framework tactic or technique"
            },
            {
                "doc_count": 66,
                "key": "Service on non-standard port"
            },
            {
                "doc_count": 64,
                "key": "Signature (capa)"
            },
            {
                "doc_count": 30,
                "key": "Signature (YARA)"
            },
            {
                "doc_count": 25,
                "key": "Signature (ClamAV)"
            },
            {
                "doc_count": 20,
                "key": "Cleartext password"
            },
            {
                "doc_count": 19,
                "key": "Long connection"
            },
            {
                "doc_count": 15,
                "key": "Notice (vulnerability)"
            },
            {
                "doc_count": 13,
                "key": "File transfer (medium concern)"
            },
            {
                "doc_count": 6,
                "key": "Notice (scan)"
            },
            {
                "doc_count": 1,
                "key": "High volume connection"
            }
        ],
        "doc_count_error_upper_bound": 0,
        "sum_other_doc_count": 0
    }
}
```
