require 'pcaprub'
require 'time'
require_relative './EthernetFrame'
require_relative './log'

OUR_WIFI_INTERFACE = "en0"
NEW_CONNECTION = "00:00:00:00:00:00"
DASH_MILK_BABY = "f0:27:2d:41:cd:83"

puts "Started at " + Time::now.to_s

capture = PCAPRUB::Pcap.open_live(OUR_WIFI_INTERFACE, 65535, true, 0)
capture.setfilter('arp')

loop do
  while (pkt = capture.next())
    packet = EthernetFrame.parse(pkt).payload.output
    sender = packet[:sender_hw_addr]
    target = packet[:target_hw_addr]

    if (sender == DASH_MILK_BABY and target == NEW_CONNECTION)
    	log_event("Pooped")
    	puts "Pooped at " + Time::now.to_s
	end
  end
  sleep 0.1
end