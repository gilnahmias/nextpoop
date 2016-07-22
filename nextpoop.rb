require 'pcaprub'
require_relative './EthernetFrame'
require_relative './log'
require 'time'

capture = PCAPRUB::Pcap.open_live('en0', 65535, true, 0)
capture.setfilter('arp')

NEW_CONNECTION = "00:00:00:00:00:00"
DASH_MILK_BABY = "f0:27:2d:41:cd:83"

puts "Started at " + Time::now.to_s

loop do
  while (pkt = capture.next())
    packet = EthernetFrame.parse(pkt).payload.output #.inspect
    sender = packet[:sender_hw_addr]
    target = packet[:target_hw_addr]

    if (sender == DASH_MILK_BABY and target == NEW_CONNECTION)
    	log_event("Pooped")
    	puts "Pooped at " + Time::now.to_s
	end
  end
  sleep 0.1
end