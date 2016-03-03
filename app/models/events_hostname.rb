class Events_Hostname < ActiveRecord::Base
  self.table_name = "events_hostname"
  self.primary_key = "host_id"
end
