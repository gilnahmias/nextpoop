require 'pcaprub'
require_relative './EthernetFrame'

capture = PCAPRUB::Pcap.open_live('en0', 65535, true, 0)
capture.setfilter('arp')

loop do
  while (pkt = capture.next())
    puts "captured!!!"
    packet = EthernetFrame.parse(pkt).payload.output #.inspect
    puts packet.inspect
    puts "sender: " + packet[:sender_hw_addr]
    puts "target: " + packet[:target_hw_addr]
  end
  sleep 0.1
end