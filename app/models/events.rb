class Events < ActiveRecord::Base
  self.table_name = "events"
  self.primary_key = "event_id"

  before_save :set_default_values
  
  def set_default_values

  	self.a_timestamp ||= ''
  	self.a_timezone ||= ''
  	self.a_date ||= '1000-01-01'
  	self.a_uniqid = ''
  	self.a_client_ip = 0
  	self.a_client_port = 0
  	self.a_server_ip = 0
  	self.a_server_port = 0

  	#a_client_ip_cc
  	#a_client_ip_asn

  	self.b_path ||= ''

  	self.f_status ||= 0
  	self.f_content_length ||= 0

  	self.h_producer = ''
  	self.h_server = ''

  	self.h_score_total = 0
  	self.h_score_SQLi = 0
  	self.h_score_total = 0
  	self.h_score_XSS = 0

  	self.preserve = false
  	self.false_positive = false

  	return true
  end
end