"""Parser unit tests — every device-facing format, no device needed."""
from __future__ import annotations

import struct

from sentinel.parsers.appops import parse_appops, parse_duration
from sentinel.parsers.camera import parse_camera_clients
from sentinel.parsers.logcat import parse_line
from sentinel.parsers.netstats import parse_netstats_detail
from sentinel.parsers.packagedump import parse_packages_dump, parse_pm_list
from sentinel.parsers.pcap import PcapStream, extract_sni, parse_dns_answers
from sentinel.parsers.procnet import is_private, parse_proc_net
from sentinel.parsers.telephony import parse_telephony_registry


# ---------------- logcat ----------------

def test_logcat_threadtime():
    ln = parse_line("10-15 18:46:01.123  1234  1300 I ActivityManager: Start proc 4711:com.foo/u0a155")
    assert ln is not None
    assert ln.pid == 1234 and ln.level == "I" and ln.tag == "ActivityManager"
    assert ln.msg.startswith("Start proc")


def test_logcat_garbage():
    assert parse_line("--------- beginning of main") is None
    assert parse_line("") is None


# ---------------- appops ----------------

APPOPS_NEW = """\
Current AppOps Service state:
  Uid u0a155:
    Package com.whatsapp:
      RECORD_AUDIO (allow):
        Access: [fgsvc-s] 2026-10-15 18:40:01.123 (-5s211ms) duration=+4s211ms
      CAMERA (allow):
        Access: [top-s] 2026-10-15 17:01:01.123 (-1h44m) duration=+10s
  Uid u0a412:
    Package com.wx.weatherpro:
      FINE_LOCATION (allow):
        Access: [cch-s] 2026-10-15 18:44:59.000 (-2s) duration=+1s
      READ_CLIPBOARD (ignore):
        Reject: [bg-s] 2026-10-15 18:44:00.000 (-61s)
"""

APPOPS_OLD = """\
  Uid 10155:
    Package com.whatsapp:
      RECORD_AUDIO: mode=allow; time=+2m3s411ms ago; duration=+5s
"""


def test_appops_new_format():
    ops = parse_appops(APPOPS_NEW)
    assert len(ops) == 4
    mic = [o for o in ops if o.op == "RECORD_AUDIO"][0]
    assert mic.package == "com.whatsapp"
    assert abs(mic.ago - 5.211) < 0.01
    assert mic.background is False and mic.rejected is False
    loc = [o for o in ops if o.op == "FINE_LOCATION"][0]
    assert loc.background is True          # cch = cached = background
    clip = [o for o in ops if o.op == "READ_CLIPBOARD"][0]
    assert clip.rejected is True and clip.background is True


def test_appops_old_format():
    ops = parse_appops(APPOPS_OLD)
    assert len(ops) == 1
    assert ops[0].op == "RECORD_AUDIO"
    assert abs(ops[0].ago - 123.411) < 0.01


def test_appops_filter():
    ops = parse_appops(APPOPS_NEW, ops={"CAMERA"})
    assert [o.op for o in ops] == ["CAMERA"]


def test_parse_duration():
    assert parse_duration("5m3s211ms") == 303.211
    assert parse_duration("1h44m") == 6240.0
    assert parse_duration("") is None
    assert parse_duration("junk") is None


# ---------------- camera ----------------

def test_camera_open_client():
    text = "Device 0 is open. Client instance dump:\n  Client package: com.instagram.android\n"
    assert parse_camera_clients(text) == {"com.instagram.android"}


def test_camera_idle():
    assert parse_camera_clients("Device 0 is closed\n Client package: com.foo") == set()


# ---------------- /proc/net ----------------

PROC_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345
   1: 0F02000A:A1B2 23D8B89D:01BB 01 00000000:00000000 00:00000000 00000000 10155        0 23456
"""

PROC_TCP6 = """\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1
   1: 0000000000000000FFFF00000F02000A:B1C2 0000000000000000FFFF0000600713D8:01BB 01 00000000:00000000 00:00000000 00000000 10203        0 2
"""


def test_proc_net_tcp4():
    socks = parse_proc_net(PROC_TCP, "tcp")
    assert len(socks) == 1                       # listener (0A) dropped
    s = socks[0]
    assert s.remote_ip == "157.184.216.35"
    assert s.remote_port == 0x01BB == 443
    assert s.uid == 10155


def test_proc_net_tcp6_mapped():
    socks = parse_proc_net(PROC_TCP6, "tcp")
    assert len(socks) == 1
    s = socks[0]
    assert s.remote_ip == "216.19.7.96"          # v4-mapped v6 is unwrapped
    assert s.uid == 10203


def test_is_private():
    assert is_private("10.0.0.5") and is_private("127.0.0.1") and is_private("192.168.1.4")
    assert not is_private("142.250.74.206")


# ---------------- netstats ----------------

NETSTATS = """\
UID stats:
  ident=[{type=WIFI, subType=COMBINED, networkId="Home", metered=false}] uid=10155 set=DEFAULT tag=0x0
    NetworkStatsHistory: bucketDuration=7200
      st=1760500800 rb=1000 rp=10 tb=500 tp=8 op=0
      st=1760508000 rb=2000 rp=20 tb=700 tp=9 op=0
  ident=[{type=MOBILE, subType=COMBINED, subscriberId=31026..., metered=true}] uid=10155 set=DEFAULT tag=0x0
    NetworkStatsHistory: bucketDuration=7200
      st=1760500800 rb=300 rp=3 tb=900 tp=5 op=0
  ident=[{type=WIFI, subType=COMBINED}] uid=10155 set=DEFAULT tag=0x1234
    NetworkStatsHistory: bucketDuration=7200
      st=1760500800 rb=99999 rp=3 tb=99999 tp=5 op=0
"""


def test_netstats_totals_and_tag_skip():
    t = parse_netstats_detail(NETSTATS)
    assert t[10155]["wifi_rx"] == 3000
    assert t[10155]["wifi_tx"] == 1200
    assert t[10155]["mobile_tx"] == 900
    # tagged bucket (tag=0x1234) must not double count
    assert t[10155]["wifi_rx"] < 10000


# ---------------- telephony ----------------

TELEPHONY = """\
mCallState=0
mServiceState=0 0 voice home data home  310260 T-Mobile ... RilDataRadioTechnology=14(LTE) ...
mCellIdentity=CellIdentityLte:{ mCi=104231 mPci=321 mTac=5021 mBands=[2] mMcc=310 mMnc=260 mOperatorAlphaLong=T-Mobile }
"""


def test_telephony_parse():
    t = parse_telephony_registry(TELEPHONY)
    assert t["call_state"] == "idle"
    assert t["network_type"] == "LTE"
    assert t["cell"]["ci"] == 104231 and t["cell"]["tac"] == 5021


# ---------------- package dumps ----------------

PM_LIST = """\
package:/data/app/~~Ab12==/com.whatsapp-Zz==/base.apk=com.whatsapp installer=com.android.vending uid:10155
package:/data/app/~~Cd34==/com.led.qrflash-Yy==/base.apk=com.led.qrflash installer=null uid:10501
"""

PKG_DUMP = """\
Packages:
  Package [com.whatsapp] (abc123):
    userId=10155
    versionCode=271024 minSdk=24 targetSdk=34
    versionName=2.26.4.78
    lastUpdateTime=2026-10-01 10:00:00
    pkgFlags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]
    signatures=PackageSignatures{a1b2c3d version:3, signatures:[6a8b96e2]}
    installSource: installerPackageName=com.android.vending, initiatingPackageName=com.android.vending
    requested permissions:
      android.permission.INTERNET
      android.permission.RECORD_AUDIO
      android.permission.CAMERA
    install permissions:
      android.permission.INTERNET: granted=true
    User 0: ceDataInode=1 installed=true
      runtime permissions:
        android.permission.RECORD_AUDIO: granted=true, flags=[ USER_SET ]
        android.permission.CAMERA: granted=false, flags=[ USER_SET ]
"""


def test_pm_list():
    pk = parse_pm_list(PM_LIST)
    assert pk["com.whatsapp"]["installer"] == "com.android.vending"
    assert pk["com.whatsapp"]["uid"] == 10155
    assert pk["com.led.qrflash"]["installer"] is None


def test_packages_dump():
    d = parse_packages_dump(PKG_DUMP)
    w = d["com.whatsapp"]
    assert w["version"] == 271024
    assert w["installer"] == "com.android.vending"
    assert w["sig"] == "6a8b96e2"
    assert "android.permission.RECORD_AUDIO" in w["requested"]
    assert "android.permission.CAMERA" in w["requested"]
    assert "android.permission.RECORD_AUDIO" in w["granted"]
    assert "android.permission.CAMERA" not in w["granted"]
    assert w["system"] is False


# ---------------- pcap / DNS / SNI ----------------

def _dns_response() -> bytes:
    hdr = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    qname = b"\x03www\x07example\x03com\x00"
    question = qname + struct.pack(">HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
    return hdr + question + answer


def _client_hello(host: bytes = b"example.org") -> bytes:
    sni_entry = b"\x00" + struct.pack(">H", len(host)) + host
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    ext = struct.pack(">HH", 0, len(sni_list)) + sni_list
    exts = struct.pack(">H", len(ext)) + ext
    body = (b"\x03\x03" + b"R" * 32          # version + random
            + b"\x00"                          # session id len
            + struct.pack(">H", 2) + b"\x13\x01"  # cipher suites
            + b"\x01\x00"                      # compression
            + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def test_dns_parse():
    res = parse_dns_answers(_dns_response())
    assert res is not None
    name, ips = res
    assert name == "www.example.com"
    assert "93.184.216.34" in ips


def test_sni_extract():
    assert extract_sni(_client_hello()) == "example.org"
    assert extract_sni(b"\x17\x03\x03\x00\x05hello") is None  # not a handshake


def _sll_udp_packet(payload: bytes, sport: int, dport: int) -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = (b"\x45\x00" + struct.pack(">H", 20 + len(udp)) + b"\x00\x00\x00\x00"
          + b"\x40\x11\x00\x00" + bytes([8, 8, 8, 8]) + bytes([10, 0, 0, 2]) + udp)
    sll = struct.pack(">HHH", 0, 1, 6) + b"\x00" * 8 + struct.pack(">H", 0x0800)
    return sll + ip


def _pcap(frames: list[bytes]) -> bytes:
    gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 113)  # SLL
    out = gh
    for f in frames:
        out += struct.pack("<IIII", 1760500000, 0, len(f), len(f)) + f
    return out


def test_pcap_stream_dns_end_to_end():
    stream = PcapStream()
    raw = _pcap([_sll_udp_packet(_dns_response(), 53, 50000)])
    pkts = []
    # feed in awkward chunk sizes to prove incremental parsing works
    for i in range(0, len(raw), 7):
        pkts.extend(stream.feed(raw[i:i + 7]))
    assert len(pkts) == 1
    p = pkts[0]
    assert p.proto == "udp" and p.sport == 53
    name, ips = parse_dns_answers(p.payload)
    assert name == "www.example.com" and "93.184.216.34" in ips


def _sll_tcp_packet(payload: bytes, sport: int, dport: int) -> bytes:
    tcp = (struct.pack(">HH", sport, dport) + b"\x00" * 8
           + bytes([5 << 4, 0x18]) + b"\x00\x00\x00\x00\x00\x00" + payload)
    ip = (b"\x45\x00" + struct.pack(">H", 20 + len(tcp)) + b"\x00\x00\x00\x00"
          + b"\x40\x06\x00\x00" + bytes([10, 0, 0, 2]) + bytes([142, 250, 74, 206]) + tcp)
    sll = struct.pack(">HHH", 4, 1, 6) + b"\x00" * 8 + struct.pack(">H", 0x0800)
    return sll + ip


def test_pcap_stream_sni_end_to_end():
    stream = PcapStream()
    raw = _pcap([_sll_tcp_packet(_client_hello(b"api.snapchat.com"), 51000, 443)])
    pkts = stream.feed(raw)
    assert len(pkts) == 1
    assert pkts[0].proto == "tcp" and pkts[0].dport == 443
    assert extract_sni(pkts[0].payload) == "api.snapchat.com"
