class Sensors < ActiveRecord::Base
  self.table_name = "sensors"
  self.primary_key = "sensor_id"
  self.inheritance_column = "inheritance_type"
end