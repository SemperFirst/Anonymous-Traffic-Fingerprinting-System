from scapy.all import *
import dpkt

class sniFF():

    def main(self,count,filter):
        count = count
        now_time = datetime.now().strftime( "%Y%m%d%H%M%S" )
        filename = r"D:\论文code\temp\sniFF_{0}.pcap".format(now_time)
        #filter = 'tcp.port == 2222'
        self.o_open_file= PcapWriter(filename, append=True)

        def callback(packet):
            packet.show()
            self.o_open_file.write(packet)
           
        dpkt_input = sniff(iface = "WLAN",count = int(count),  filter='{}'.format(filter),prn = callback)
    
 
if __name__ == '__main__':
    sniFF().main(3,'TCP')
    