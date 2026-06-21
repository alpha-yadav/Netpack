import dissector as d
import argparse,datetime
import scapy.all as sc
class PacketAnalyzer:
    def __init__(self,args:argparse.ArgumentParser=None):
        self.app={"http":"80","dns":"53","ssh":"22","telnet":"23","smtp":"25",
                  "rdp":"3389","ftp":["20","21"],"ntp":"123","pop3":"101","dhcp":["67","68"]}
        self.count=0
        self.argx=args.parse_args()
        self.args=self._arg_parser(self.argx)
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
        if(self.argx.save):
            sc.wrpcap(self.argx.save,pkt=pkt,append=True)
        print(f"[{datetime.datetime.now().strftime("%H:%M.%S")}]:{d.dissect(pkt)}")
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
    pt=PacketAnalyzer(args)
    pt.run()