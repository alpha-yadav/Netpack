import dissector as d
import argparse,datetime
import scapy.all as sc
from stats import  SynScanDetector
class PacketAnalyzer:
    def __init__(self,args:argparse.ArgumentParser=None):
        self.app={"http":"80","dns":"53","ssh":"22","telnet":"23","smtp":"25",
                  "rdp":"3389","ftp":["20","21"],"ntp":"123","pop3":"101","dhcp":["67","68"]}
        self.count=0
        self.argx=args.parse_args()
        self.args=self._arg_parser(self.argx)
        self.scan_detector = (
            SynScanDetector(port_threshold=self.argx.scan_threshold) if self.argx.scan_threshold else None
        )
    def _arg_parser(self,args:argparse.ArgumentParser)->dict:
        redict={"count":args.count,"iface":args.iface}
        filter_=args.network if args.network else []
        filter_=filter_+args.tranport if args.tansport else filter_
        app=[f"port {i}" if type(i)==str else f"port {i[0]} and port{i[1]}"
              for i in args.application ] if args.application else []
        filter_=" and ".join(app+filter_)
        filter_+=" and "+args.filter if args.filter else ""
        redict["filter"]=filter_
        return redict
    def _packet_handler(self,pkt):
        self.count+=1
        if(self.argx.save):
            sc.wrpcap(self.argx.save,pkt=pkt,append=True)
        layers=d.dissect(pkt)
        self._print_packet(layers)
        if self.scan_detector and "tcp" in layers and "ip" in layers:
            alert = self.scan_detector.observe(
                src_ip=layers["ip"]["src_ip"],
                dst_port=layers["tcp"]["dst_port"],
                tcp_flags=layers["tcp"]["flags"],
            )
            if alert:
                print(f"  !! ALERT: {alert.message}")
    def _print_packet(self, layers: dict) -> None:
        parts = [f"#{self.count} | "]
        if "ethernet" in layers:
            eth=layers["ethernet"]
            parts.append(f"{eth["src_mac"]} -> {eth["dst_mac"]} | ") 
        if "ip" in layers:
            ip = layers["ip"]
            parts.append(f"{ip['src_ip']} -> {ip['dst_ip']} (ttl={ip['ttl']})")
        if "ip6" in layers:
            ip = layers["ip6"]
            parts.append(f"{ip['src_ip']} -> {ip['dst_ip']}")
        if "tcp" in layers:
            tcp = layers["tcp"]
            parts.append(
                f"TCP {tcp['src_port']}->{tcp['dst_port']} [{tcp['flags']}] "
                f"({tcp['flags_meaning']})"
            )
        elif "udp" in layers:
            udp = layers["udp"]
            parts.append(f"UDP {udp['src_port']}->{udp['dst_port']} len={udp['length']}")

        if "dns" in layers:
            dns = layers["dns"]
            if "query_name" in dns:
                parts.append(f"DNS query: {dns['query_name']}")
            if "resolved_to" in dns:
                parts.append(f"DNS resolved -> {dns['resolved_to']}")

        if "http" in layers:
            parts.append(f"HTTP: {layers['http']['first_line']}")

        if "tls_sni" in layers:
            parts.append(f"TLS SNI: {layers['tls_sni']}")

        print(" ".join(parts))
    def run(self):
        self.args["prn"]=self._packet_handler
        sc.sniff(**self.args)
if __name__=="__main__":
    args=argparse.ArgumentParser()
    args.add_argument("-c","--count",default=0,type=int,help="No of packets")
    args.add_argument("-l1","--application",nargs="+",default=None,help="Application Layer protocol like HTTP and FTP")
    args.add_argument("-l2","--tansport",nargs="+",default=None,help="Tansport layer protocol like TCP and UDP")
    args.add_argument("-l3","--network",nargs="+",default=None,help="Network layer protocol like IPv6 and ICMP")
    args.add_argument("-f","--filter",default=None, help="Filter of packets")
    args.add_argument("-s","--save",default=None,help="Write captured packets to this .pcap file on exit.")
    args.add_argument("-i","--iface",default=None,help="Network interface (e.g. eth0, wlan0). Default: all interfaces.")
    args.add_argument("-sh","--scan-threshold",type=int,default=None,help="Distinct ports within the detector's window before a scan alert fires.")
    pt=PacketAnalyzer(args)
    pt.run()