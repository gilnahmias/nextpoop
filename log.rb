require 'net/http'
require 'time'

CLOUD_STITCH_URL = "http://api.cloudstitch.com/gilnalhmias/nextpoop/datasources/sheet"

def log_event (eventId)
	timestamp = Time::now
	uri = URI(CLOUD_STITCH_URL)
	res = Net::HTTP.post_form(uri, 'Timestamp' => timestamp, 'Event' => eventId)
end


