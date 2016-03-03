class Events_Full_Sections < ActiveRecord::Base
  self.table_name = "events_full_sections"
  # self.primary_key = "event_id"

  before_save :set_default_values
  
  def set_default_values
    
    self.z_full ||= '' 

    return true
  end
end