#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <array>
#include <cctype>
#include "L1.h"

extern "C" {
#include "shake.h"
}

// =============================================================================
// VALORI UFFICIALI OPENSSL FIPS 204 PER ML-DSA-44 CON SEED = 0x00...00
// =============================================================================

const std::string OPENSSL_PUB_RAW = R"(
    ba:71:f9:f6:4e:11:ba:eb:58:fa:9c:6f:bb:6e:14:
    e6:1f:18:64:3d:ab:49:5b:47:53:9a:91:66:ca:01:
    98:13:1c:44:f8:26:bb:d5:6e:34:e5:5d:b5:e5:e2:
    d7:33:48:5e:39:ea:26:0f:c6:00:0c:5e:a4:ba:80:
    d3:45:5c:de:53:b4:6f:34:48:2a:ed:fd:54:50:fc:
    2e:1b:a4:f2:5d:15:f9:c1:44:24:2f:b3:9b:b5:22:
    87:18:90:30:c5:04:98:e1:71:7b:7c:75:8b:19:0a:
    67:48:ea:9a:a3:f7:ac:aa:f2:c7:cb:52:6e:d7:17:
    c9:f7:9a:eb:84:21:4f:a5:cd:8d:ed:92:a0:c3:fa:
    15:58:81:0f:12:c7:05:0a:36:77:08:d1:96:cd:24:
    e5:af:97:49:04:ae:d8:e4:ce:88:72:e8:69:6b:0b:
    7b:ca:50:e4:52:cd:7d:30:ea:9a:4a:da:c0:31:1d:
    67:2c:6b:de:84:96:24:0b:07:43:14:63:70:88:95:
    cd:9b:af:c3:16:32:d7:39:76:49:38:8f:da:fc:bf:
    7d:30:5a:3d:e9:a4:95:ec:a7:43:3a:8f:83:ba:0f:
    0b:25:c4:13:c6:e3:9c:96:eb:7d:69:1b:34:d3:7c:
    e3:7f:1e:ea:d1:cf:21:7e:25:ef:34:ee:cf:3f:7c:
    60:f8:4b:8e:df:dd:e8:40:5d:4f:83:25:76:c6:1e:
    f9:8e:0a:2f:28:da:18:77:00:95:39:24:f6:86:b9:
    46:14:70:5b:cf:53:d3:3f:ed:d4:34:8e:dd:db:df:
    28:b5:06:5e:1f:20:77:50:43:e8:5c:f9:31:f8:29:
    17:93:63:a1:a7:e7:40:4a:83:8e:c0:00:86:b0:97:
    63:86:fe:63:7c:98:24:47:57:e3:f7:69:dd:d4:46:
    74:71:bf:ad:67:0f:9a:05:f8:24:6e:e5:0a:7b:1e:
    af:87:fc:40:69:c3:ae:2a:a2:03:32:58:11:77:92:
    f0:bc:d4:9e:08:3f:d1:bc:74:96:ab:ff:29:cc:94:
    e4:86:8b:21:21:4e:d3:16:52:53:99:a6:10:fb:dd:
    4a:80:e7:c8:07:15:f2:95:78:e2:a8:4b:b4:0b:dd:
    db:d9:f4:7a:11:b6:e7:da:11:8a:1b:65:8d:35:9e:
    8a:ef:55:eb:46:b5:37:6b:5b:65:59:79:98:4a:92:
    2b:ee:bf:c5:9b:cd:60:0d:53:09:dc:cd:72:db:f0:
    78:7d:b8:ba:75:7b:53:7c:1e:af:d5:c0:f5:0e:a4:
    bc:95:83:54:9e:28:29:a4:2c:28:ca:c2:48:c9:6d:
    78:12:4c:47:15:9b:18:ae:dd:75:4a:ba:17:b1:9d:
    43:0f:b7:8f:63:3e:a9:d2:6f:54:a9:bd:50:f8:d8:
    f6:b7:35:94:f8:28:97:6e:7e:a0:9c:53:bb:b9:f1:
    1a:56:c9:50:7f:b8:9b:9a:5e:bc:03:7a:37:26:7a:
    95:f8:5b:8d:64:ca:97:19:2b:10:a6:6f:41:7b:3f:
    61:fe:9c:a5:71:30:a4:8f:d9:25:ea:e2:ab:55:02:
    d5:71:c8:a5:19:03:c1:d3:98:f4:c1:f7:6a:7e:11:
    74:39:76:af:db:c6:97:f2:30:94:a3:cd:76:1f:f9:
    68:5d:e3:2e:09:fb:3c:28:ad:d4:53:49:03:00:bc:
    7c:89:dc:01:78:00:96:07:17:22:94:57:75:f2:64:
    e1:b0:62:3b:cf:46:19:c7:12:c8:38:76:12:05:d8:
    76:91:b7:5e:f3:60:19:6c:bb:9e:9b:92:a0:d4:c4:
    ed:62:32:6e:50:24:d7:75:10:b8:ee:2c:74:26:cc:
    22:ea:e2:09:dc:9f:13:bd:e6:bf:08:f5:e7:18:1b:
    d3:b4:59:45:0b:45:1a:51:53:9a:71:5c:21:d6:7d:
    d3:30:eb:59:70:db:00:d9:ed:bf:b2:82:2b:03:6f:
    a1:3b:af:eb:86:d8:dc:78:86:6e:3f:8d:43:e5:3d:
    78:cc:a5:59:5a:6f:af:88:6b:5d:c1:12:f1:cf:4a:
    dc:fa:87:58:00:d9:0b:48:88:3a:f9:73:16:fe:15:
    06:87:3f:c1:57:e5:70:ea:cb:fd:22:28:68:d1:42:
    34:10:19:66:af:b6:bf:99:40:82:92:53:a9:53:ad:
    a8:9f:c7:56:b6:a8:49:f7:0a:cb:98:38:e6:9f:aa:
    50:bb:a7:5e:3e:89:c2:ad:b5:7e:86:d0:88:ab:9b:
    04:a2:8e:67:07:09:17:22:43:ec:5e:00:08:a5:ce:
    af:3f:87:22:f4:87:30:25:96:ff:d7:55:ad:1b:82:
    a4:9c:34:b3:46:95:15:b4:6a:a2:90:cd:86:ee:38:
    ea:7a:9b:e3:f1:03:61:03:35:b5:31:cc:a3:33:dd:
    fe:32:b1:45:10:f4:b0:7e:f9:5f:c6:68:4e:8c:45:
    4a:92:c1:0d:bb:5d:59:c7:a7:c6:3f:b3:05:fe:88:
    19:67:d9:9e:66:9e:b6:32:84:05:82:56:0b:b4:03:
    43:1d:40:f7:5a:49:54:90:84:82:27:82:92:82:1f:
    4e:a9:1e:42:e7:8f:a4:8c:ae:e3:c8:36:14:6d:cf:
    d7:38:d1:17:e9:2e:9a:15:13:7d:28:e8:e6:a4:b4:
    62:26:50:cb:41:35:04:cb:3a:33:5d:44:be:ec:57:
    46:c1:c2:94:b1:e8:cb:99:cb:60:8d:92:8f:8c:e3:
    56:36:32:c5:21:f2:3d:13:c6:1a:8f:61:c0:1d:f8:
    c9:6c:73:60:db:4f:3c:68:aa:5d:2f:dd:34:2a:62:
    ff:34:59:c1:16:38:94:21:ab:43:e8:58:4c:45:88:
    2b:50:e6:e4:e9:6d:b6:f0:b8:fd:e8:90:d5:db:fa:
    dc:d8:86:90:b4:49:e6:42:40:dd:b2:02:37:47:f3:
    08:36:3e:30:1a:a7:77:57:16:9f:c6:15:06:28:d5:
    92:0b:5a:a1:ab:1c:8c:bf:44:cb:00:e0:25:d7:87:
    9d:72:b4:79:e3:af:53:11:c7:85:72:55:90:da:9c:
    89:b9:fc:3b:84:50:76:95:54:eb:44:d2:03:eb:a2:
    bb:ae:f9:ca:d2:23:70:11:c2:ea:44:ef:f0:0f:29:
    9a:48:ff:e2:8c:a9:3d:df:85:f7:66:08:24:2e:f8:
    d6:cc:24:61:0a:1e:20:78:fc:ac:4f:93:85:c3:14:
    90:5e:ca:a8:2e:55:39:16:d9:4d:1a:7c:1e:c6:52:
    aa:08:89:70:83:da:a2:eb:b1:77:5f:bc:47:1a:e2:
    77:77:d7:90:4e:a9:f1:b9:2b:ca:c3:d8:a3:15:84:
    26:08:7b:64:5b:11:08:f0:d6:5f:ec:93:78:9c:05:
    37:43:ca:14:fd:63:d0:5e:98:b6:52:df:2b:9c:2f:
    f9:ce:05:f1:94:07:03:ff:b2:73:f8:0e:0e:27:32:
    ec:a9:96:0d:98:1b:4c:fd:3b:7b:b8:04:5b:3c:38:
    30:54:6b:9d:d8:db:0d
)";

const std::string OPENSSL_PRIV_RAW = R"(
    ba:71:f9:f6:4e:11:ba:eb:58:fa:9c:6f:bb:6e:14:
    e6:1f:18:64:3d:ab:49:5b:47:53:9a:91:66:ca:01:
    98:13:c5:c1:61:0a:40:77:4f:0e:ba:33:34:f8:b5:
    be:56:e8:78:71:b3:c3:a7:72:c0:72:0f:a3:76:66:
    ae:17:35:fd:e6:bc:38:a1:c3:5f:8c:f0:8e:44:09:
    24:c9:03:71:97:bb:87:fd:c4:64:6b:86:da:5a:05:
    89:a3:26:cc:0c:0d:95:0f:f8:b5:a9:ea:41:35:ea:
    b8:a9:3f:80:f0:92:7e:12:40:46:e2:5b:23:66:ae:
    a2:5a:6d:1d:0f:ef:98:21:04:b8:09:da:12:48:e1:
    40:4c:11:03:85:99:b0:4d:61:04:0a:c0:34:28:23:
    16:80:08:12:45:11:49:0c:a0:96:0d:c2:a8:01:5a:
    a8:65:0b:30:25:d4:94:44:8b:38:8c:10:24:41:22:
    40:69:8a:04:04:0c:26:90:e3:34:69:e2:24:68:d2:
    44:00:0b:84:90:d9:42:30:21:91:8d:09:99:64:20:
    39:60:82:36:21:90:b8:4c:02:12:6e:24:b9:70:84:
    22:01:e1:a8:64:44:26:0e:01:17:0e:82:40:6c:9b:
    38:6d:0a:93:50:52:22:25:d2:b8:2c:1a:25:70:90:
    12:22:d1:b2:80:22:46:52:01:34:80:40:34:21:41:
    06:60:41:32:82:09:45:90:52:32:29:83:b8:44:93:
    12:21:0a:c1:89:60:b2:71:9c:90:69:90:82:90:89:
    12:49:40:40:8a:5c:10:48:01:87:91:03:b0:40:d8:
    44:05:e4:b0:29:0a:27:90:1c:c9:50:58:02:8c:0c:
    49:72:49:84:6d:19:a7:85:e3:00:30:cb:b2:21:e2:
    08:10:4c:a6:64:11:43:68:52:94:69:09:39:32:91:
    a2:6d:ca:14:84:a3:92:11:db:94:2c:01:c6:64:14:
    24:8c:1a:15:31:0a:23:0e:d8:14:20:a4:26:8d:43:
    40:90:c1:42:86:a4:10:85:0c:32:2d:d0:28:60:1b:
    b5:0c:52:44:61:21:15:24:21:c6:04:d8:34:31:d9:
    12:71:a2:34:52:03:30:89:54:32:10:83:94:08:a2:
    a4:70:d2:44:8e:84:02:8d:91:46:62:0b:00:0e:a0:
    80:70:22:b5:0d:0b:c9:01:00:26:4d:e2:44:80:93:
    20:65:c9:96:8d:da:a4:4c:42:a8:00:1a:27:6c:c3:
    94:4d:a0:30:2c:da:a8:04:23:a3:8c:63:04:0e:59:
    c8:00:20:a9:6c:c4:06:50:82:00:2e:5c:b2:44:61:
    46:51:0c:18:80:18:38:82:02:25:90:a2:b2:60:21:
    a0:40:20:49:2a:52:28:86:93:a6:28:9b:94:71:02:
    b9:6d:49:a0:2c:09:25:28:18:93:09:10:49:4c:13:
    c9:91:a3:88:2d:50:12:31:63:b4:00:a4:00:4e:04:
    b6:68:12:14:26:00:17:00:9b:92:0c:51:a8:65:11:
    44:8d:44:42:69:00:a5:6d:04:a9:69:43:94:69:4c:
    b8:60:52:26:2d:a1:32:11:ca:b0:11:1b:81:90:12:
    11:64:42:86:89:9c:12:51:dc:c0:41:13:47:68:9b:
    20:92:d1:26:91:23:96:50:13:b3:4c:12:45:69:21:
    a1:05:0c:46:65:99:38:30:99:26:2e:19:15:72:11:
    39:8d:89:10:92:50:28:11:48:a6:49:52:b6:2d:c9:
    30:4d:d9:32:91:91:a6:44:14:34:0e:13:39:41:98:
    06:0c:22:25:6c:14:47:70:21:b7:60:23:98:25:e4:
    24:6e:d1:b6:44:51:44:2c:41:42:85:e0:44:42:89:
    42:42:c2:24:2c:cc:c6:68:13:12:69:98:30:49:23:
    28:6a:14:c8:11:60:92:30:11:26:52:92:b0:00:5c:
    84:2c:4a:14:29:0a:95:40:e3:c4:05:0c:c8:89:a1:
    26:62:44:10:04:9a:c8:70:0c:93:60:90:b6:30:12:
    17:71:23:18:4e:d4:10:85:84:20:82:5c:14:48:90:
    b2:51:a0:18:92:93:94:80:1a:49:72:c0:02:06:e1:
    a6:8c:a1:80:4d:4a:26:08:18:07:62:42:12:40:10:
    41:64:44:42:4e:94:86:40:9a:84:41:21:c5:71:01:
    96:29:19:40:4e:94:36:22:24:c3:20:22:88:71:84:
    20:4c:64:20:69:db:84:24:24:25:46:21:c4:71:8a:
    14:64:01:20:65:4c:84:24:44:24:30:8a:22:70:d3:
    86:30:0b:b4:6c:21:23:0a:8b:b8:4d:5c:f7:d7:e6:
    89:30:2b:ed:b1:c5:86:7e:7d:26:9b:1c:db:07:f8:
    25:64:10:82:e1:9a:8d:a2:f9:30:77:e8:b1:fc:3d:
    4e:6b:2d:32:58:33:6b:4f:9c:64:55:15:3a:c0:40:
    a8:47:fb:64:7f:bb:6b:55:2a:40:00:71:fe:17:72:
    48:5b:7a:9d:1f:0d:14:7b:f3:38:8c:56:54:71:e4:
    e6:2c:c3:ce:0d:0c:0f:c3:60:df:92:89:ed:99:18:
    37:6b:8b:8b:93:14:50:47:f8:fe:a2:98:60:07:c2:
    aa:89:92:2f:69:eb:47:5b:59:7b:2b:ba:23:7b:9c:
    84:2e:3f:f1:d3:25:e8:2a:1f:23:e9:49:89:d0:06:
    bc:7c:e4:94:6f:2e:8b:77:e1:08:48:46:3c:47:fe:
    7b:20:9e:2a:61:7d:dd:41:79:6a:e6:14:5e:70:9c:
    da:94:06:f2:26:12:57:c2:13:b4:b3:0d:a3:0a:c2:
    5b:0d:06:cf:79:a8:12:c5:fc:b0:ef:11:d9:fe:df:
    e0:99:4a:fe:3b:69:b0:6a:29:16:cf:69:2b:9d:a7:
    60:28:e5:f3:a0:48:79:e6:96:d2:1f:73:5c:37:83:
    15:36:4d:b0:a4:e0:ab:6b:53:d3:1e:fa:f3:0d:65:
    e3:7a:1b:6a:77:04:6f:04:c6:4b:a1:07:2a:97:80:
    e0:c5:66:c9:43:39:a4:d1:9d:00:68:c5:7d:6e:6f:
    0b:51:2d:b7:13:4a:95:0e:af:4f:7b:01:a5:fd:d0:
    65:b9:1b:fa:29:e4:42:36:79:cd:e7:4b:c6:a8:f1:
    c8:4c:4d:f7:83:87:23:1d:c8:5c:e3:26:70:44:59:
    03:c4:be:be:e3:f5:0c:43:e5:04:49:49:69:11:aa:
    93:e7:e3:95:78:74:14:d3:17:68:d9:91:25:20:f8:
    3c:02:ff:01:12:4d:cf:0e:12:5f:af:d5:b9:d7:e7:
    dd:a4:f5:b5:0c:70:ae:bb:85:99:a2:e4:47:6a:0d:
    e5:31:b0:40:26:72:df:75:75:14:2d:86:01:60:5c:
    94:01:79:23:f6:4a:c5:77:c4:be:d8:d8:e8:9a:74:
    ca:9f:38:19:cb:f1:42:a7:2d:eb:e7:7c:4e:fb:71:
    27:e2:d8:c1:b7:bf:b6:42:86:c0:bd:52:23:3f:43:
    c6:7d:57:17:f9:7a:d8:28:54:87:3d:dc:7f:71:d6:
    56:aa:a6:ef:70:70:60:af:28:0b:9f:45:4b:4f:ed:
    b4:77:6e:83:b2:fd:ba:20:a4:5a:ef:eb:54:9a:1e:
    d0:38:20:21:89:3c:a9:a6:e7:4c:cc:30:a2:55:39:
    37:cc:ef:34:38:99:b5:02:cf:46:dd:b8:dd:1d:95:
    fe:fb:60:c9:b2:04:69:a1:50:3b:2a:68:75:87:83:
    0d:33:ce:e9:a7:2d:79:8f:cf:4a:9b:45:2c:85:49:
    f5:59:c5:d9:fc:6b:fe:08:3f:44:6c:2d:90:39:81:
    d9:f2:64:92:48:3a:b4:52:ea:5b:b1:00:8f:fe:ac:
    97:5d:a0:27:59:59:3e:7e:06:63:61:07:3a:83:b2:
    7b:53:1a:3d:0d:da:51:7c:a9:90:ea:32:35:d1:d7:
    b5:e0:9d:a5:f0:2d:c1:52:5b:1d:a6:85:96:5b:54:
    fc:2a:3a:73:a1:79:0e:0e:fb:69:e7:0a:78:fa:55:
    03:44:ea:8c:75:3d:bf:18:63:9b:aa:8c:b1:25:9a:
    a7:4f:68:f9:2a:ba:80:07:c6:18:cc:b6:f5:06:9f:
    f4:6b:97:51:bb:ff:f3:7d:f3:21:36:0f:0f:5c:0e:
    7f:56:26:dd:12:9a:e3:ae:2a:7c:56:cd:b6:11:ed:
    a4:c9:8f:ec:83:16:3c:d5:11:68:78:c1:a9:3e:ba:
    a2:6d:b4:05:ea:f4:a7:ab:a2:77:83:7d:e9:a5:15:
    04:70:76:24:ef:2e:1b:bb:ca:29:24:11:16:7f:2e:
    3d:39:0c:0e:51:f8:4a:2f:13:83:90:e3:3f:85:83:
    5d:38:a9:4d:bb:e7:1e:6c:82:1e:86:b1:1f:fd:89:
    ef:f4:bf:e2:08:d6:00:5d:28:f7:04:ba:ea:d1:f2:
    5d:e0:eb:24:1b:18:fc:7f:a0:dd:d9:0d:c1:39:be:
    7f:cb:eb:97:30:fa:e4:b5:d1:72:70:ce:4c:67:0c:
    42:57:0a:9c:f2:5b:c4:fa:e5:cd:31:e5:d5:5a:d0:
    22:6a:94:be:52:94:8c:67:02:a9:86:a0:ad:bf:cd:
    3a:c4:82:bb:12:ab:bb:79:a2:f6:60:28:42:15:3b:
    2f:82:a3:b3:cd:16:88:e7:4d:36:53:4b:ff:8c:48:
    d3:c4:51:eb:2c:5f:98:fe:b9:e7:86:4d:60:af:96:
    e8:3b:21:62:46:74:82:f0:58:63:9c:86:a7:85:a9:
    a1:d4:b6:9b:c3:0e:77:a6:4c:3b:bc:d7:de:b4:e3:
    d3:0f:1a:67:21:20:3d:87:a8:8a:b8:5e:02:7a:97:
    42:fc:68:8f:0a:df:15:72:8e:59:7e:91:0c:fe:5d:
    f3:3c:56:a1:36:ef:39:c7:ca:5d:65:0c:2b:9f:90:
    1c:9b:89:e1:e0:93:54:93:61:f3:03:be:88:39:d1:
    45:4c:ce:b5:fb:c4:43:5f:a0:da:b5:8a:8f:c2:85:
    36:0e:ea:49:1c:a0:77:96:1c:4a:aa:3e:96:de:99:
    71:b9:4f:df:a5:20:7c:cf:0d:9d:ab:2c:48:96:f0:
    7e:b6:77:1a:38:3c:65:12:f4:1e:a2:8d:ee:e4:07:
    fd:ae:3c:57:4f:5d:41:6a:89:7a:27:ef:7c:f5:96:
    f0:43:2d:62:4a:2c:4e:ac:e5:2f:3c:bf:2c:63:31:
    b8:0c:9c:91:65:bf:13:34:24:69:32:02:4e:c0:be:
    44:b3:21:36:b4:e4:34:27:91:35:85:03:64:c7:57:
    f1:dc:fa:63:85:e2:56:33:12:c5:f5:53:f0:c8:44:
    ea:bb:79:11:ce:e7:60:ca:eb:3e:19:3b:f3:a9:c3:
    81:14:87:23:9a:d2:e0:14:78:f4:6e:41:8a:5d:e5:
    6b:7f:17:55:ba:68:f9:a3:74:61:3b:5d:e2:ed:26:
    c5:80:c7:72:db:db:fa:b1:f7:e3:f5:7d:94:f8:4e:
    30:de:b2:9d:70:a9:1d:f2:88:fc:43:a2:76:df:ed:
    58:e2:b0:db:53:83:e5:32:b6:ee:df:b3:92:e4:3d:
    c3:da:72:01:a0:68:f5:23:1e:e5:22:09:8d:68:59:
    b2:d5:64:63:a8:91:7b:3c:25:61:65:79:66:db:c4:
    78:56:b6:ff:c8:2b:cc:37:9f:fd:08:b2:59:f3:d9:
    d7:87:3b:a8:fc:be:4c:94:13:b6:01:15:91:60:70:
    1d:f0:04:70:b1:49:bd:f3:2f:4d:3c:fc:fb:9d:eb:
    c7:72:41:71:7d:13:06:7a:ae:d2:3c:7a:26:51:18:
    51:69:f1:26:70:61:fb:6b:30:e4:fe:a7:3f:66:f4:
    f9:27:56:ac:26:23:41:8a:f8:b2:a3:98:71:1b:7c:
    68:07:b4:34:25:e1:d9:9b:fd:cd:5d:f5:31:95:28:
    79:06:a3:32:f5:99:71:a0:c3:43:97:5f:c3:20:ad:
    13:7c:9e:34:ce:7c:e8:55:20:b2:6c:a1:97:a1:fa:
    2d:f2:ec:d4:e3:fa:83:3b:3b:d2:c2:44:82:80:42:
    52:cf:1d:f6:ad:c6:39:8f:35:e9:8a:b1:87:10:40:
    76:80:c9:c1:db:ac:8c:7e:dc:86:46:b9:70:82:e2:
    e1:21:fa:a7:fa:c2:1e:4a:33:83:84:cb:92:20:2c:
    61:bd:12:6c:5d:dd:45:8b:32:7a:18:bd:71:6f:14:
    2c:a5:cd:b3:e4:9d:7e:b8:d9:62:b5:b8:5a:88:f7:
    99:b6:9a:6a:66:c7:bd:62:9f:56:b4:3c:02:90:62:
    9b:5e:27:4c:de:c7:a0:72:29:e7:93:9a:77:d3:2e:
    8e:f7:30:fc:ce:ad:9c:4e:06:77:a8:3a:03:30:ab:
    76:5d:33:6d:d2:aa:15:5d:cd:2a:c7:f3:15:29:77:
    4f:49:36:b0:5d:0b:14:b4:8f:aa:1e:8c:d4:50:56:
    e5:6c:13:9b:17:f8:90:71:5a:d6:3d:6c:4a:9f:2d:
    97:6c:8b:63:5b:df:e5:86:02:81:6f:61:2c:6e:4b:
    22:53:67:cb:9a:7b:b7:9c:01:8f:1b:8c:53:15:18:
    0a:ad:be:3a:b7:5a:c3:56:20:6f:e2:7c:12:df:3b:
    56:97:84:e3:a5:38:fb:05:24:18:26:6e:72:db:40:
    0d:6f:32:c4:29:7f:34:f9:f1:af:18:6c:37:65:65:
    5f:11:b3:e5:a3:c8:04:9b:7d:f1:40:11:ff:21:5f:
    bf:17:bf:89:ee:97:6c:f0:db:ab:62:70:10:4e:7e:
    31:9d:1f:64:c5:9e:20:9e:35:82
)";

std::string clean_openssl_hex(const std::string& input) {
    std::string out;
    for (char c : input) {
        if (std::isxdigit(c)) out += (char)std::tolower(c);
    }
    return out;
}

std::string to_hex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    for (size_t i = 0; i < len; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return ss.str();
}

void run_nist_fips204_kat(L1& dev, uint16_t level) {
    std::cout << "\n=== [NIST KAT] VERIFICA FIPS 204 CONTRO OPENSSL REFERENCE ===" << std::endl;

    std::string ref_pk = clean_openssl_hex(OPENSSL_PUB_RAW);
    std::string ref_sk = clean_openssl_hex(OPENSSL_PRIV_RAW);

    // FIX 1: Quanti byte reali di SK abbiamo fornito?
    size_t known_sk_bytes = ref_sk.length() / 2;

    // FIX 2: Se la stringa è troncata, la riempiamo di zeri fino a raggiungere 2560 byte
    // esattamente come faceva il padding nell'array C.
    if (ref_sk.length() < 2560 * 2) {
        std::cout << "[INFO] OPENSSL_PRIV_RAW troncata. Effettuo il padding con zeri per "
                  << (2560 - known_sk_bytes) << " byte mancanti di t0..." << std::endl;
        ref_sk.append((2560 * 2) - ref_sk.length(), '0');
    }

    // FIPS 204 ML-DSA-44 Dimensioni esatte
    if (ref_pk.length() != 1312 * 2 || ref_sk.length() != 2560 * 2) {
        std::cout << "[!] Errore interno: La lunghezza della reference OpenSSL fornita non corrisponde a ML-DSA-44." << std::endl;
        return;
    }

    std::vector<uint8_t> pk, sk;

    // Il firmware deve avere il seme forzato a zero: memset(zeta, 0x00, 32);
    dev.L1_ML_DSA_Keygen(level, pk, sk);

    if (pk.size() < 1312 || sk.size() < 2560) {
        std::cout << "  [!] Dimensioni chiavi generate non valide per ML-DSA-44!" << std::endl;
        return;
    }

    std::string hsm_pk = to_hex(pk.data(), 1312);
    std::string hsm_sk = to_hex(sk.data(), 2560);

    // Estrazione e confronto dei singoli blocchi per debug avanzato
    auto check_block = [](const std::string& name, const std::string& hsm, const std::string& ref, size_t offset, size_t len) {
        std::string hsm_sub = hsm.substr(offset * 2, len * 2);
        std::string ref_sub = ref.substr(offset * 2, len * 2);
        std::cout << "\n[CHECK] " << name << " (offset " << offset << ", " << len << " byte):" << std::endl;
        std::cout << "  HSM: " << hsm_sub.substr(0, 32) << "... (tot: " << len << " bytes)" << std::endl;
        std::cout << "  REF: " << ref_sub.substr(0, 32) << "... (tot: " << len << " bytes)" << std::endl;
        std::cout << (hsm_sub == ref_sub ? "  -> MATCH OK ✅" : "  -> FAIL ❌") << std::endl;
    };

    std::cout << "\n--- ANALISI PUBLIC KEY ---" << std::endl;
    check_block("Rho (Seme Matrice A)", hsm_pk, ref_pk, 0, 32);
    check_block("t1  (Polinomi compressi)", hsm_pk, ref_pk, 32, 1280);

    std::cout << "\n--- ANALISI SECRET KEY ---" << std::endl;
    check_block("Rho (Seme Matrice A)", hsm_sk, ref_sk, 0, 32);
    check_block("K   (Seme per firma)", hsm_sk, ref_sk, 32, 32);
    check_block("tr  (Hash della PK)", hsm_sk, ref_sk, 64, 64);
    check_block("s1  (Vettore segreto)", hsm_sk, ref_sk, 128, 384);
    check_block("s2  (Errore)", hsm_sk, ref_sk, 512, 384);

    // Per t0, controlliamo solo la parte che abbiamo effettivamente (sottraendo l'offset 896)
    size_t known_t0_len = (known_sk_bytes > 896) ? (known_sk_bytes - 896) : 0;
    if (known_t0_len > 0) {
        check_block("t0  (Polinomi scarto PARZIALI forniti)", hsm_sk, ref_sk, 896, known_t0_len);
    }

    std::cout << "\n[INFO] La restante parte di t0 non verra' verificata poiche' non fornita nella reference raw." << std::endl;

    // Calcolo locale TR per doppia verifica (deve usare ESATTAMENTE 1312 byte)
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, pk.data(), 1312);
    shake256_finalize(&state);
    uint8_t calculated_tr[64];
    shake256_squeeze(calculated_tr, 64, &state);

    std::string calc_tr_hex = to_hex(calculated_tr, 64);
    std::string hsm_tr_hex = hsm_sk.substr(64 * 2, 64 * 2);

    std::cout << "\n[CHECK] Verifica integrita' tr locale vs HSM:" << std::endl;
    std::cout << "  CALC: " << calc_tr_hex.substr(0, 32) << "..." << std::endl;
    std::cout << "  HSM : " << hsm_tr_hex.substr(0, 32) << "..." << std::endl;
    std::cout << (hsm_tr_hex == calc_tr_hex ? "  -> MATCH OK ✅" : "  -> FAIL ❌") << std::endl;

    // FIX 3: La verifica finale controlla tutta la PK, ma solo la porzione NOTA della SK
    bool pk_match = (hsm_pk == ref_pk);
    bool sk_match_known = (hsm_sk.substr(0, known_sk_bytes * 2) == ref_sk.substr(0, known_sk_bytes * 2));

    if (pk_match && sk_match_known) {
        std::cout << "\n>>> SUCCESSO ASSOLUTO: L'HSM produce una coppia di chiavi matematicamente e binariamente identica al target OpenSSL FIPS 204 (per tutti i byte forniti)! <<<" << std::endl;
    } else {
        std::cout << "\n>>> FALLIMENTO: Analizza i blocchi sopra per capire dove la matematica differisce. Se fallisce Rho, l'HSM sta ancora generando numeri casuali reali. <<<" << std::endl;
    }
}

int main() {
    L1 dev;
    std::array<uint8_t, 32> pin = {'t', 'e', 's', 't'};
    dev.L1Login(pin, SE3_ACCESS_USER, true);
    run_nist_fips204_kat(dev, 2);
    dev.L1Logout();
    return 0;
}