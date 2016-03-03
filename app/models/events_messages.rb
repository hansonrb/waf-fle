class Events_Messages < ActiveRecord::Base
  self.table_name = "events_messages"
  self.primary_key = "msg_id"
end