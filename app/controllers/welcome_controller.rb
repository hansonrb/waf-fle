require 'base64'
require 'uri'
require 'geoip'

class WelcomeController < ApplicationController
  COMPRESSION = true

  def initialize 
  	@outputbuffer = ''
  end

  def index
  	echo_init

    # mlog2waffle_debug = false
    matches = [];
    http_header = { 'USER' => '', 'PASS' => '' }

    request.headers.each do |header, value|
      if header.casecmp('Authorization')
      	next if !value.instance_of? String
        matches = value.scan(/^Basic\s([0-9a-zA-Z]+\={0,2})$/)

        next if matches.blank?

        matches2 = Base64.decode64(matches[1]).scan( /^([0-9a-z\.\_\-]{5,30}):([0-9a-z\.\_\-\,\\?\\\|\!\@\#\$\%\&\*\(\)\=\+\[\]\{\}\>\<]{5,20})/i )

        http_header['USER'] = matches2[1].downcase
        http_header['PASS'] = matches2[2]
      end
      #if header == 'X-WAFFLE-Debug'
      #  mlog2waffle_debug = true if value == 'ON'
      #end
    end

    remote_address = request.remote_ip

    login_status = sensorLogin( remote_address, matches[1], http_header['USER'], http_header['PASS'] )
    #login_status = sensorLogin( '172.18.18.104', matches[1], 'sensor1', 'abc123' )

    if login_status.present? && login_status['status'] == 1
      sensor_id = login_status['sensor_id']
      #helper:apache_setenv('REMOTE_USER', login_status['sensor_name'])
    elsif login_status.present? && login_status['status'] == 0
      response.headers['Status'] = '403'
      abort( '403' )
    else
      response.headers['Status'] = '500'
      #print 'Authentication Error\n' if mlog2waffle_debug
      abort( 'Authentication Error' )
    end

    if login_status['sensor_client_ip_header'].present?
      client_ip_header_reg_exp = '^' + login_status['sensor_client_ip_header'] + ':\s([12]?[0-9]{1,2}\.[12]?[0-9]{1,2}\.[12]?[0-9]{1,2}\.[12]?[0-9]{1,2})'
    end

    # Body: read and treatment
    # body = file('php://input')
    body = request.body.read.split('\n')
    line = 0
    body_size = body.count

    phase_a = {}
    phase_b = {}
    phase_f = {}
    phase_h_msg = {}
    phase_h = { "Score" => {} }

    while line < body_size do
      if body[line].strip.scan( /^WAF\-FLE\ PROBE/i ).present?
        # Probe ok, exiting now 
        response.headers['X-WAF-FLE'] = 'READY';
        response.headers['Status'] = '200';
        print 'WAF-FLE: READY\n'
        return
      end

      # Phase A
      if body[line].strip.scan( /^\-\-[a-f0-9]+\-A\-\-$/i ).present?
        phase_a_full = nil
        

        # audit log header (mandatory)
        while line < body_size do
          if body[line].strip.scan(/^\-\-[a-f0-9]+\-[BCEFHIKZ]\-\-$/i ).present?
            break
          else
            matches_a = body[line].strip.scan( /^\[(\d{1,2})\/(\w{3})\/(\d{4})\:(\d{2}\:\d{2}\:\d{2})\s(\-\-\d{4}|\+\d{4})\]\s([a-zA-Z0-9\-\@]{24})\s([12]?[0-9]{1,2}\.[12]?[0-9]{1,2}\.[12]?[0-9]{1,2}\.[12]?[0-9]{1,2})\s(\d{1,5})\s([12]?[0-9]{1,2}\.[12]?[0-9]{1,2}\.[12]?[0-9]{1,2}\.[12]?[0-9]{1,2})\s(\d{1,5})/i )
            
            if matches_a.present?
              phase_a['Day'] = matches_a[1]
              months = [nil, 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

              months.each_with_index do |month, key|
                phase_a['Month'] = key if month == matches_a[2]
              end

              phase_a['Year']       = matches_a[3]
              phase_a['Hour']       = matches_a[4]
              phase_a['Timestamp']  = matches_a[3] + '-' + phase_a['Month'] + '-' + matches_a[1] + ' ' + matches_a[4]
              phase_a['Timezone']   = matches_a[5]
              phase_a['Date']       = matches_a[3] + '-' + phase_a['Month'] + '-' + matches_a[1]
              phase_a['UniqID']     = matches_a[6]
              phase_a['ClientIP']   = matches_a[7]
              phase_a['SourcePort'] = matches_a[8]
              phase_a['ServerIP']   = matches_a[9]
              phase_a['ServerPort'] = matches_a[10]
            end
            phase_a_full = phase_a_full + body[line]
            line+=1
          end
        end
      end
      # Phase B
      if body[line].strip.scan('/^\-\-[a-f0-9]+\-B\-\-$/i').present?
        phase_b_full = nil
        phase_b = [];

        while line < body_size do
          if body[line].strip.scan(/^\-\-[a-f0-9]+\-[ACEFHIKZ]\-\-$/i).present?
            break
          else
            if ( matches_b = body[line].strip.scan( /^(GET|POST|HEAD|PUT|DELETE|TRACE|PROPFIND|OPTIONS|CONNECT|PATCH)\s(.+)\s(HTTP\/[01]\.[019])/i ) ).present?
              phase_b['Method']        = matches_b[1]
              phase_b['pathParameter'] = parse_url('http://dummy.ex' + matches_b[2], PHP_URL_QUERY)
              # pathParsed             = parse_url(matches_b[2], PHP_URL_PATH)
              phase_b['path']          = parse_url('http://dummy.ex' + matches_b[2], PHP_URL_PATH)
              phase_b['Protocol']      = matches_b[3]
            elsif ( matches_b = body[line].strip.scan( /^Host:\s(.+)/i ) ).present?
              phase_b['Host'] = matches_b[1]
            elsif ( matches_b = body[line].strip.scan( /^Content-Type:\s([\w\-\/]+)\\s([\w\-\\.\/\*\+\=\:\?\,\s\(\)]+)/i ) ).present?
              phase_b['Content-Type'] = matches_b[1]
            elsif ( matches_b = body[line].strip.scan( /^Referer:\s(.+)/i ) ).present?
              phase_b['Referer'] = matches_b[1]
            elsif ( matches_b = body[line].strip.scan( /^User-Agent:\s(.+)/i ) ).present?
              phase_b['User-Agent'] = matches_b[1]
            elsif login_status['sensor_client_ip_header'] != 1 && ( matches_b = body[line].strip.scan( /$clientIpHeaderRegExp/i ).present? )
              phase_a['ClientIP'] = matches_b[1]  # Set Client IP (to Phase A) when a HTTP Header is defined to carry real client ip, and sensor are marked to respect this
            end

            phase_b_full = phase_b_full + body[line]
            line+=1
          end
        end
      end

      # Phase C
      if body[line].strip.scan( /^\-\-[a-f0-9]+\-C\-\-$/i ).present?
        phase_c_full = nil
        phase_c_line0 = line
        while line < body_size do
          phase_c_pass = line - phase_c_line0
          if body[line].strip.scan( /^\-\-[a-f0-9]+\-[ABEFHIKZ]\-\-$/i ).present?
            break
          elsif  phase_c_pass > 100
            line+=1
          else
            phase_c_full = phase_c_full + body[line].slice( 0, 4096 )
            line+=1
          end
        end
      end

      # Phase E
      if body[line].strip.scan( /^\-\-[a-f0-9]+\-E\-\-$/i ).present?
        phase_e_full = nil
        while line < body_size do
          if body[line].strip.scan( /^\-\-[a-f0-9]+\-[ABCFHIKZ]\-\-$/i ).present?
            break
          else
            phase_e_full = phase_e_full + body[line]
            line+=1
          end
        end
      end

      # Phase F
      if body[line].strip.scan( /^\-\-[a-f0-9]+\-F\-\-$/i ).present?
        phase_f_full = nil
        while line < body_size do
          if body[line].strip.scan( /^\-\-[a-f0-9]+\-[ABCEHIKZ]\-\-$/i ).present?
            break
          else
            if (matches_f = body[line].strip.scan( /^(HTTP\/\d\.\d)\s(\d\d\d)\s([\w\s]+)/i ) ).present?
              phase_f['Protocol'] = matches_f[1]
              phase_f['Status']   = matches_f[2]
              phase_f['MSG']      = matches_f[3]
            elsif ( matches_f = body[line].strip.scan( /^Content-Length:\s(\d+)/i ) ).present?
              phase_f['Content-Length'] = matches_f[1]
            elsif ( matches_f = body[line].strip.scan( /^Connection:\s([\w-]+)/i ) ).present?
              phase_f['Connection'] = matches_f[1]
            elsif ( matches_f = body[line].strip.scan( '/^Content-Type:\s((?:[\w\-\/]+)(?:\)?(?:\s)?(?:[\w\-\\.\/\*\+\=\:\?\,\s\(\)]+)?)/i' ) ).present?
              phase_f['Content-Type'] = matches_f[1]
              phase_f_full = phase_f_full + body[line]
              line+=1
            end
          end
        end
      end

      # Phase H

      if body[line].strip.scan( /^\-\-[a-f0-9]+\-H\-\-$/i ).present?
        phase_h_full = nil
        hline = 0
        
        while line < body_size do
          if body[line].strip.scan( /^\-\-[a-f0-9]+\-[ABCEFIKZ]\-\-$/i ).present?
            break
          else
            # Is a message line?
            current_h_line = body[line].strip
            
            if current_h_line.scan(/^Message:\s/i).present?
              message_start = 0
              # look for message Action
              if ( matches_h = current_h_line.scan( /^Message:\s((Warning|Access|Paus)(.*?))\.\s/i ) ).present?
                phase_h_msg[hline]['Message_Action'] = matches_h[1]

                ActionStatus.each do |key, statusValue|
                  if matches_h[1].scan ( '/'+statusValue+'/i' ).present?
                    if phase_h['ActionStatus'].present? && phase_h['ActionStatus'] > key
                      phase_h['ActionStatus']    = key
                      phase_h['ActionStatusMsg'] = matches_h[1]
                    elsif phase_h['ActionStatus'].blank?
                      phase_h['ActionStatus']    = key
                      phase_h['ActionStatusMsg'] = matches_h[1]
                    end
                  end
                end

                message_start  = curreht_h_line.index('. ') + 2
              else
                message_start  = 9
              end

              #Execution error - PCRE limit exceeded handling
              if body[line].strip.scan('/Execution\serror\s-\sPCRE\slimits\sexceeded/').present?
                phase_h_msg[hline]['Message_Msg'] = 'Execution Error - PCRE limit exceeded'
                phase_h_msg[hline]['Message_RuleId'] = pcre_err_rule_id

                pcre_rule_id = body[line].strip.scan( /id\s\"(\d+)\"/ )

                phase_h_msg[hline]['Message_Data'] = 'RuleId:' + pcre_rule_id[1]
                phase_h_full = phase_h_full + body[line]
                hline+=1
                line+=1
                next
              end

              # look for Pattern 
              # include workaround to make compatible with libinject broken log format
              message_stop  = current_h_line.index( ' [file', message_start )
              message_length = message_stop - message_start
              pattern =  current_h_line.slice( message_start, message_length )
              phase_h_msg[hline]['Message_Pattern'] = (pattern.present ? rtrim(pattern, '.') : nil)
              message_start = message_stop

              # look for metadata
              while true do
                message_start = current_h_line.index( ' [', message_start )

                break if message_start.nil?

                message_stop = current_h_line.index( '\"] ', message_start )
                if message_stop.nil?
                  message_stop = current_h_line.index( '\"]', message_start )
		  	          message_stop = current_h_line.length if message_stop.nil?
                end

                message_length = message_stop - message_start
                msg_content = current_h_line.slice( message_start, message_length )

                message_start = message_stop

                # look for File
                message_file = strstr_after(msg_content, '[file ', true)
                if message_file
                  phase_h_msg[hline]['Message_File'] = message_file
                  next
                end

                # look for line
                message_line = strstr_after(msg_content, '[line ', true)
                if message_line
                  phase_h_msg[hline]['Message_Line'] = message_line
                  next
                end

                # look for rev
                message_rev = strstr_after(msg_content, '[rev ', true)
                if message_rev
                  phase_h_msg[hline]['Message_Rev'] = message_rev
                  next
                end

                # look for Rule Id
                message_ruleid = strstr_after(msg_content, '[id ', true)
                if message_ruleid
                  phase_h_msg[hline]['Message_RuleId'] = message_Ruleid
                  next
                end

                # look for data
                message_data = strstr_after(msg_content, '[data ', true)
                if message_data
                  phase_h_msg[hline]['Message_Data'] = message_data
                  next
                end

                # look for tags
                message_tag = strstr_after(msg_content, '[tag ', true)
                if message_tag
                  phase_h_msg[hline]['Message_Tag'][] = getTagID(message_tag)
                  next
                end

                # look for severity
                message_severity = strstr_after(msg_content, '[severity ', true)
                if message_severity
                  phase_h_msg[hline]['Message_Severity'] = array_search(message_severity, severity)
                  next
                end

                # look for msg
                message_Msg = strstr_after(msg_content, '[msg ', true)
                if message_Msg
                  phase_h_msg[hline]['Message_Msg'] = message_Msg

                  # Get Scores from msg
                  if ( score = message_Msg.scan( '/Inbound Anomaly Score \(Total\sInbound\sScore:\s?(?P<In_Total>[\d]{1,4})?,\sSQLi=(?P<In_SQLi>[\d]{1,4})?,\s?XSS=(?P<In_XSS>[\d]{1,4})?/i' ) ).present?
                    phase_h['Score']['In_Total'] = score['In_Total'] if score['In_Total'].present? && score['In_Total'] > phase_h['Score']['In_Total']
                    phase_h['Score']['In_SQLi'] = score['In_SQLi'] if score['In_SQLi'].present? && score['In_SQLi'] > phase_h['Score']['In_SQLi']
                    phase_h['Score']['In_XSS'] = score['In_XSS'] if score['In_XSS'].present? && score['In_XSS'] > phase_h['Score']['In_XSS']
                  elsif ( score = message_Msg.scan( '/Inbound Anomaly Score Exceeded \(Total\sScore:\s?(?P<In_Total>[\d]{1,4})?,\sSQLi=(?P<In_SQLi>[\d]{1,4})?,\s?XSS=(?P<In_XSS>[\d]{1,4})?/i' ) ).present?
                    phase_h['Score']['In_Total'] = score['In_Total'] if score['In_Total'].present? && score['In_Total'] > phase_h['Score']['In_Total']
                    phase_h['Score']['In_SQLi'] = score['In_SQLi'] if score['In_SQLi'].present? && score['In_SQLi'] > phase_h['Score']['In_SQLi']
                    phase_h['Score']['In_XSS'] = score['In_XSS'] if score['In_XSS'].present? && score['In_XSS'] > phase_h['Score']['In_XSS']
                  elsif ( score = message_Msg.scan( '/Anomaly Score Exceeded \(score (?P<In_Total>\d{1,10})\):\s?(?P<trigger>.+)/i' ) ).present?
                    phase_h['Score']['In_Total'] = score['In_Total'] if score['In_Total'].present? && score['In_Total'] > phase_h['Score']['In_Total']
                  end
                  next
                end
              end
              hline+=1

            elsif ( matches_h = body[line].strip.scan( /^Apache-Error:\s(?:\[file\s\"([\w\/\-\.]+)\"\].?)?(?:\[line\s(\d+)\].?)?(?:\[level\s(\d+)\].?)?([\w\:\/\.\-,\?\=\s]+)?/i ) ).present?
              phase_h['Apache_error-File']    = ( matches_h[1].present? ? matches_h[1] : nil)
              phase_h['Apache_error-Line']    = ( matches_h[2].present? ? matches_h[2] : nil)
              phase_h['Apache_error-Level']   = ( matches_h[3].present? ? matches_h[3] : nil)
              phase_h['Apache_error-Message'] = ( matches_h[4].present? ? matches_h[4].strip : nil)
            elsif ( matches_h = body[line].strip.scan( /^Action: Intercepted\s.*(\d)/i ) ).present?
              phase_h['Interception_phase'] = ( matches_h[1].present? ? matches_h[1] : nil)
            elsif ( matches_h = body[line].strip.scan( /^Stopwatch:\s(\d{16})\s([\d\-]+)\s\(([\d\-\*]+)\s([\d\-]+)\s([\d\-]+)\)/i ) ).present?
              phase_h['Stopwatch_Timestamp']         = ( matches_h[1].present? ? matches_h[1] : nil)  # number of microseconds since 00:00:00 january 1, 1970 UTC
              phase_h['Stopwatch_Duration']          = ( matches_h[2].present? ? matches_h[2] : nil)
              phase_h['Stopwatch_time_checkpoint_1'] = ( matches_h[3].present? ? matches_h[3] : nil)
              phase_h['Stopwatch_time_checkpoint_2'] = ( matches_h[4].present? ? matches_h[4] : nil)
              phase_h['Stopwatch_time_checkpoint_3'] = ( matches_h[5].present? ? matches_h[5] : nil)
            elsif ( matches_h = body[line].strip.scan( /^Stopwatch2:\s(\d{16})\s([\d\-]+)\scombined=(\d+),\sp1=(\d+),\sp2=(\d+),\sp3=(\d+),\sp4=(\d+),\sp5=(\d+),\ssr=(\d+),\ssw=(\d+),\sl=(\d+),\sgc=(\d+)$/i ) ).present?
              phase_h['Stopwatch2_Timestamp']         = ( matches_h[1].present? ? matches_h[1] : nil)  # number of microseconds since 00:00:00 january 1, 1970 UTC
              phase_h['Stopwatch2_duration']          = ( matches_h[2].present? ? matches_h[2] : nil)
              phase_h['Stopwatch2_combined'] = ( matches_h[3].present? ? matches_h[3] : nil)  # combined processing
              phase_h['Stopwatch2_p1'] = ( matches_h[4].present? ? matches_h[4] : nil)  # phase 1 duration
              phase_h['Stopwatch2_p2'] = ( matches_h[5].present? ? matches_h[5] : nil)  # phase 2 duration
              phase_h['Stopwatch2_p3'] = ( matches_h[6].present? ? matches_h[6] : nil)  # phase 3 duration
              phase_h['Stopwatch2_p4'] = ( matches_h[7].present? ? matches_h[7] : nil)  # phase 4 duration
              phase_h['Stopwatch2_p5'] = ( matches_h[8].present? ? $matches_h[8] : nil)  # phase 5 duration
              phase_h['Stopwatch2_sr'] = ( matches_h[9].present? ? matches_h[9] : nil)  # persistent storage read duration
              phase_h['Stopwatch2_sw'] = ( matches_h[10].present? ? matches_h[10] : nil) # persistent storage write duration
              $phase_h['Stopwatch2_l'] = ( matches_h[11].present? ? matches_h[11] : nil)  # time spent on audit log
              phase_h['Stopwatch2_gc'] = ( matches_h[12].present? ? matches_h[12] : nil)  # time spend on garbage collection
            elsif ( matches_h = body[line].strip.scan( /^(?:Producer|WAF):\s(.+\.)$/i ) ).present?
              if ( matches_h = body[line].strip.scan( /(.+)\s(.+)\.$/i ) ).present?
                phase_h['Producer']         = ( prod[1].present? ? prod[1] : nil)
                phase_h['Producer_ruleset'] = ( prod[2].present? ? prod[2] : nil)
              else
                phase_h['Producer']         = ( matches_h[1].present? ? matches_h[1] : nil)
                phase_h['Producer_ruleset'] = nil
              end
            elsif ( matches_h = body[line].strip.scan( /^Server:\s(.+)/i ) ).present?
              phase_h['Server'] = ( matches_h[1].present? ? matches_h[1] : nil)
            elsif ( matches_h = body[line].strip.scan( /^WebApp-Info:\s\"(.+)\"\s\"(.+)\"\s\"(.+)\"/i ) ).present?
              phase_h['WebApp-Info_Application_ID'] = ( matches_h[1].present? ? matches_h[1] : nil)
              phase_h['WebApp-Info_Session_ID']     = ( matches_h[2].present? ? matches_h[2] : nil)
              phase_h['WebApp-Info_User_ID']        = ( matches_h[3].present? ? matches_h[3] : nil)
            elsif ( matches_h = body[line].strip.scan( /^Apache-Handler:\s(.+)/i ) ).present?
              phase_h['Apache-Handler'] = ( matches_h[1].present? ? matches_h[1] : nil)
            elsif ( matches_h = body[line].strip.scan( /^Response-Body-Transformed:\s(.+)/i ) ).present?
              phase_h['Response-Body-Transformed'] = ( matches_h[1].present? ? matches_h[1] : nil)
            elsif ( matches_h = body[line].strip.scan( /^Engine-Mode:\s"(\S+)"/i ) ).present?
              phase_h['Engine_Mode'] = ( matches_h[1].present? ? strtoupper(matches_h[1]) : nil)
            end
            phase_h_full = phase_h_full + body[line]
            line+=1
          end
        end
      end

      # Phase I
      if body[line].strip.scan( /^\-\-[a-f0-9]+\-I\-\-$/i ).present?
        phase_i_full = nil
        while line < body_size do
          if body[line].strip.scan( /^\-\-[a-f0-9]+\-[ABCEFHKZ]\-\-$/i ).present?
            break
          else
            phase_i_full = phase_i_full + body[line]
            line+=1
          end
        end
      end

      # Phase K
      if body[line].strip.scan( /^\-\-[a-f0-9]+\-K\-\-$/i ).present?
        phase_k_full = nil
        while line < body_size do
          if body[line].strip.scan( /^\-\-[a-f0-9]+\-[ABCEFHIZ]\-\-$/i ).present?
            break
          else
            phase_k_full = phase_k_full + body[line]
            line+=1
          end
        end
      end

      #Phase: Z (the end)
      if body[line].strip.scan( /^\-\-[a-f0-9]+\-Z\-\-$/i ).present?
        phase_z_full = nil
        while line < body_size do
          if body[line].strip.scan( /^\-\-[a-f0-9]+\-[ABCEFHIK]\-\-$/i ).present?
            break
          else
            phase_z_full = phase_z_full + body[line]
            line+=1
          end
        end
      end
      # Match phases not yet implemented
      if body[line].strip.scan( /^\-\-[a-f0-9]+\-[^ABCEFHIKZ]\-\-$/i ).present?
        while line < body_size do
          if body[line].strip.scan( /^\-\-[a-f0-9]+\-[ABCEFHIKZ]\-\-$/i ).present?
            break
          else
            line+=1
          end
        end
      end
    end


    # Set a mark in RelevantOnly events trapped by sensor but not trapped by a rule
    if phase_h_msg.blank?
      phase_h['Message_Severity'] = 99
      phase_h['Message_Tag']      = 'TRANSACTION'
    else
      phase_h_msg = array_values(arrayUnique(phase_h_msg))

      phase_h_msg.each do |msg_severit|
        if phase_h['Message_Severity'].blank?
          if msg_severity['Message_Severity'].blank?
            phase_h['Message_Severity'] = msg_severity['Message_Severity']
          end
        elsif msg_severity['Message_Severity'].present? && phase_h['Message_Severity'] > msg_severity['Message_Severity']
          phase_h['Message_Severity'] = msg_severity['Message_Severity']
        end
      end
    end

    # Set event as Pass (99) when no Interception_phase is defined, Pass can be a Action "pass, allowed" or can be "Detection Only"

    phase_h['Interception_phase'] = 99 if phase_h['Interception_phase'].blank?

    # Hack to avoid handle IPv6 by now

    if phase_a['ClientIP'] == '' || phase_a['ServerIP'] == ''
      response.headers['Status'] = '200';
      print '\nIPv6 not supported by now, sorry\n'

      return
    end

    # Insert event in database
    #sql_event = 'INSERT INTO `events` (`event_id`, `sensor_id`, `a_timestamp`, `a_timezone`,`a_date`,`a_uniqid`, `a_client_ip`,`a_client_ip_cc`,`a_client_ip_asn`, `a_client_port`, `a_server_ip`, `a_server_port`, `b_method`, `b_path`,`b_path_parameter`,`b_protocol`, `b_host`, `b_user_agent`, `b_referer`, `f_protocol`, `f_status`, `f_msg`,`f_content_length`, `f_connection`, `f_content_type`, `h_apache_error_file`, `h_apache_error_line`,`h_apache_error_level`, `h_apache_error_message`, `h_stopwatch_timestamp`, `h_stopwatch_duration`,`h_stopwatch_time_checkpoint_1`, `h_stopwatch_time_checkpoint_2`, `h_stopwatch_time_checkpoint_3`,  `h_stopwatch2_Timestamp`, `h_stopwatch2_duration`, `h_stopwatch2_combined`, `h_stopwatch2_p1`, `h_stopwatch2_p2`, `h_stopwatch2_p3`, `h_stopwatch2_p4`, `h_stopwatch2_p5`, `h_stopwatch2_sr`, `h_stopwatch2_sw`, `h_stopwatch2_l`, `h_stopwatch2_gc`, `h_producer`,`h_producer_ruleset`, `h_server`, `h_wa_info_app_id`, `h_wa_info_sess_id`, `h_wa_info_user_id`, `h_apache_handler`,`h_response_body_transf`,`h_severity`,`h_action_status`,`h_action_status_msg`,`h_engine_mode`,`h_score_total`,`h_score_SQLi`,`h_score_XSS`,`h_Interception_phase`) VALUES (nil, :sensorid, :phase_aTimestamp, :phase_aTimezone, :phase_aDate, :phase_aUniqID, INET_ATON(:phase_aClientIP),:phase_aclient_ip_cc, :phase_aclient_ip_asn, :phase_aSourcePort, INET_ATON(:phase_aServerIP), :phase_aServerPort,  :phase_bMethod, :phase_bPath, :phase_bPathParameter, :phase_bProtocol, :phase_bHost, :phase_bUserAgent, :phase_bReferer, :phase_fProtocol, :phase_fStatus, :phase_fMSG, :phase_fContentLength, :phase_fConnection, :phase_fContentType, :phase_hApacheerrorFile, :phase_hApacheerrorLine, :phase_hApacheerrorLevel, :phase_hApacheerrorMessage, :phase_hStopwatchTimestamp, :phase_hStopwatchDuration, :phase_hStopwatchtimecheckpoint1, :phase_hStopwatchtimecheckpoint2, :phase_hStopwatchtimecheckpoint3, :phase_hStopwatch2_Timestamp, :phase_hStopwatch2_duration, :phase_hStopwatch2_combined, :phase_hStopwatch2_p1,  :phase_hStopwatch2_p2, :phase_hStopwatch2_p3, :phase_hStopwatch2_p4, :phase_hStopwatch2_p5, :phase_hStopwatch2_sr, :phase_hStopwatch2_sw, :phase_hStopwatch2_l, :phase_hStopwatch2_gc, :phase_hProducer, :phase_hProducerruleset, :phase_hServer, :phase_hWebAppInfoApplicationID, :phase_hWebAppInfoSessionID, :phase_hWebAppInfoUserID, :phase_hApacheHandler, :phase_hResponseBodyTransformed, :phase_hSeverity, :phase_hActionStatus, :phase_hActionStatusMsg, :phase_hEngineMode, :phase_hScoreInTotal, :phase_hScoreInSQLi, :phase_hScoreInXSS, :phase_hInterception_phase)'

    phase_b['Method'] = '' if phase_b['Method'].blank?
    phase_b['path'] = '' if phase_b['path'].blank?
    phase_b['pathParameter'] = '' if phase_b['pathParameter'].blank?
    phase_b['Protocol'] = '' if phase_b['Protocol'].blank?
    phase_b['Host'] = '' if phase_b['Host'].blank?
    phase_b['User-Agent'] = '' if phase_b['User-Agent'].blank?
    phase_b['Referer'] = '' if phase_b['Referer'].blank?
    phase_f['Content-Length'] = '' if phase_f['Content-Length'].blank?
    phase_f['Connection'] = '' if phase_f['Connection'].blank?
    phase_f['Content-Type'] = '' if phase_f['Content-Type'].blank?
    phase_f['MSG'] = '' if phase_f['MSG'].blank?
    phase_f['Protocol'] = '' if phase_f['Protocol'].blank?

    phase_h['Apache_error-File'] = '' if phase_h['Apache_error-File'].blank?
    phase_h['Apache_error-Line'] = '' if phase_h['Apache_error-Line'].blank?
    phase_h['Apache_error-Level'] = '' if phase_h['Apache_error-Level'].blank?
    phase_h['Apache_error-Message'] = '' if phase_h['Apache_error-Message'].blank?
    phase_h['WebApp-Info_Application_ID'] = '' if phase_h['WebApp-Info_Application_ID'].blank?
    phase_h['WebApp-Info_Session_ID'] = '' if phase_h['WebApp-Info_Session_ID'].blank?
    phase_h['WebApp-Info_User_ID'] = '' if phase_h['WebApp-Info_User_ID'].blank?
    phase_h['Apache-Handler'] = '' if phase_h['Apache-Handler'].blank? 
    phase_h['Response-Body-Transformed'] = '' if phase_h['Response-Body-Transformed'].blank?
    phase_h['ActionStatus'] = '20' if phase_h['ActionStatus'].blank? 
    phase_h['ActionStatusMsg'] = 'Warning' if phase_h['ActionStatusMsg'].blank?
    phase_h['Engine_Mode'] = nil if phase_h['Engine_Mode'].blank? 
    phase_h['Message_Severity'] = '99' if phase_h['Message_Severity'].blank? 

    begin
      insert_sth = Events.new

      insert_sth.sensor_id = sensor_id
      insert_sth.a_timestamp = phase_a['Timestamp']
      insert_sth.a_timezone = phase_a['Timezone']
      insert_sth.a_date = phase_a['Date']
      insert_sth.a_uniqid = phase_a['UniqID']
      insert_sth.a_client_ip = phase_a['ClientIP']

      # Get Country Code of IP Address
      client_ip_cc = geoip_country_code_by_name(phase_a['ClientIP'])
      
      if client_ip_cc.blank? || client_ip_cc = '--'
         client_ip_cc = nil
      end

      # Get Country Code of IP ASN
      # client_ip_asn = str_ireplace('AS', '', strstr(geoip_isp_by_name(phase_a['ClientIP']), ' ', true))

      client_ip_asn = geoip_isp_by_name(phase_a['ClientIP']).split(' ').first

      if client_ip_asn.present?
        client_ip_asn = client_ip_asn.gsub( '/as/i', '' ) 
      else
        client_ip_asn = '0'
      end

      if client_ip_asn.blank?  
         client_ip_asn = '0'
      end

      insert_sth.a_client_ip_cc = client_ip_cc
      insert_sth.a_client_ip_asn = client_ip_asn
      insert_sth.a_client_port = phase_a['SourcePort']
      insert_sth.a_server_ip = phase_a['ServerIP']
	    insert_sth.a_server_port = phase_a['ServerPort']
	    insert_sth.b_method = phase_b['Method']
	    insert_sth.b_path = phase_b['Path']
	    insert_sth.b_path_parameter = phase_b['pathParameter']

      webHostID = getWebHostID(phase_b['Host'])    

      insert_sth.b_protocol = phase_b['Protocol']
      insert_sth.b_host = webHostID
      insert_sth.b_user_agent = phase_b['User-Agent']
      insert_sth.b_referer = phase_b['Referer']
      insert_sth.f_protocol = phase_f['Protocol']
      insert_sth.f_status = phase_f['Status']
      insert_sth.f_msg = phase_f['MSG']
      insert_sth.f_content_length = phase_f['Content-Length']
      insert_sth.f_connection = phase_f['Connection']
      insert_sth.f_content_type = phase_f['Content-Type']
      insert_sth.h_apache_error_file = phase_h['Apache_error-File']
      insert_sth.h_apache_error_line = phase_h['Apache_error-Line']
      insert_sth.h_apache_error_level = phase_h['Apache_error-Level']
      insert_sth.h_apache_error_message = phase_h['Apache_error-Message']
      insert_sth.h_stopwatch_timestamp = phase_h['Stopwatch_Timestamp']
      insert_sth.h_stopwatch_duration = phase_h['Stopwatch_Duration']
      insert_sth.h_stopwatch_time_checkpoint_1 = phase_h['Stopwatch_time_checkpoint_1']
      insert_sth.h_stopwatch_time_checkpoint_2 = phase_h['Stopwatch_time_checkpoint_2']
      insert_sth.h_stopwatch_time_checkpoint_3 = phase_h['Stopwatch_time_checkpoint_3']
      insert_sth.h_stopwatch2_Timestamp = phase_h['Stopwatch2_Timestamp']
      insert_sth.h_stopwatch2_duration = phase_h['Stopwatch2_duration']
      insert_sth.h_stopwatch2_combined = phase_h['Stopwatch2_combined']
      insert_sth.h_stopwatch2_p1 = phase_h['Stopwatch2_p1']
      insert_sth.h_stopwatch2_p2 = phase_h['Stopwatch2_p2']
      insert_sth.h_stopwatch2_p3 = phase_h['Stopwatch2_p3']
      insert_sth.h_stopwatch2_p4 = phase_h['Stopwatch2_p4']
      insert_sth.h_stopwatch2_p5 = phase_h['Stopwatch2_p5']
      insert_sth.h_stopwatch2_sr = phase_h['Stopwatch2_sr']
      insert_sth.h_stopwatch2_sw = phase_h['Stopwatch2_sw']
      insert_sth.h_stopwatch2_l = phase_h['Stopwatch2_l']
      insert_sth.h_stopwatch2_gc = phase_h['Stopwatch2_gc']
      insert_sth.h_producer = phase_h['Server']
      insert_sth.h_producer_ruleset = phase_h['Producer_ruleset']
      insert_sth.h_server = phase_h['Server']
      insert_sth.h_wa_info_app_id = phase_h['WebApp-Info_Application_ID']
      insert_sth.h_wa_info_sess_id = phase_h['WebApp-Info_Session_ID']
      insert_sth.h_wa_info_user_id = phase_h['WebApp-Info_User_ID']
      insert_sth.h_apache_handler = phase_h['Apache-Handler']
      insert_sth.h_response_body_transf = phase_h['Response-Body-Transformed']
      insert_sth.h_severity = phase_h['Message_Severity']
      insert_sth.h_action_status = phase_h['ActionStatus']
      insert_sth.h_action_status_msg = phase_h['ActionStatusMsg']
      insert_sth.h_engine_mode = phase_h['Engine_Mode']
      insert_sth.h_score_total = phase_h['Score']['In_Total']
      insert_sth.h_score_SQLi = phase_h['Score']['In_SQLi']
      insert_sth.h_score_XSS = phase_h['Score']['In_XSS']
      insert_sth.h_Interception_phase = phase_h['Interception_phase']

      insert_sth.save!

      event_id = insert_sth.event_id

    rescue 
		  raise
      # response.headers['Status'] = '500';
      # abort( "Error (insert events)" )
      # return
    end

    # Insert event full section in database
    # sql_eventFullSections = 'INSERT INTO `events_full_sections` (`event_id`, `a_full`, `b_full`, `c_full`, `e_full`, `f_full`, `h_full`, `i_full`, `k_full`, `z_full`, `compressed`) VALUES (:eventid, :phase_a_full, :phase_b_full, :phase_c_full, :phase_e_full, :phase_f_full, :phase_h_full, :phase_i_full, :phase_k_full, :phase_z_full, :Compressed)'

    phase_c_full = '' if phase_c_full.blank?
    phase_e_full = '' if phase_e_full.blank?
    phase_h_full = '' if phase_h_full.blank?
    phase_i_full = '' if phase_i_full.blank?
    phase_k_full = '' if phase_k_full.blank?

    begin
      phase_a_fullCompress = COMPRESSION ? gzcompress(phase_a_full): phase_a_full
      phase_b_fullCompress = COMPRESSION ? gzcompress(phase_b_full): phase_b_full
      phase_c_fullCompress = COMPRESSION ? gzcompress(phase_c_full): phase_c_full
      phase_e_fullCompress = COMPRESSION ? gzcompress(phase_e_full): phase_e_full
      phase_f_fullCompress = COMPRESSION ? gzcompress(phase_f_full): phase_f_full
      phase_h_fullCompress = COMPRESSION ? gzcompress(phase_h_full): phase_h_full
      phase_i_fullCompress = COMPRESSION ? gzcompress(phase_i_full): phase_i_full
      phase_k_fullCompress = COMPRESSION ? gzcompress(phase_k_full): phase_k_full

      insertFull_sth = Events_Full_Sections.new
      insertFull_sth.event_id = event_id
      insertFull_sth.a_full = phase_a_fullCompress
      insertFull_sth.b_full = phase_b_fullCompress
      insertFull_sth.c_full = phase_c_fullCompress
      insertFull_sth.e_full = phase_e_fullCompress
      insertFull_sth.f_full = phase_f_fullCompress
      insertFull_sth.h_full = phase_h_fullCompress
      insertFull_sth.i_full = phase_i_fullCompress
      insertFull_sth.k_full = phase_k_fullCompress
      insertFull_sth.z_full = phase_z_full
      insertFull_sth.compressed = COMPRESSION

      insertFull_sth.save!
    rescue 
      response.headers['Status'] = '500';
      raise
      # abort( "Error (event full sections)" )
    end

    if phase_h_msg.kind_of?(Array) && event_id.present?

      #sql_event_message = 'INSERT INTO `events_messages` (`event_id`, `h_message_pattern`, `h_message_action`, `h_message_ruleFile`,`h_message_ruleLine`, `h_message_ruleId`, `h_message_ruleData`, `h_message_ruleSeverity`) VALUES (:eventid,  :MessagePattern, :MessageAction, :MessageFile, :MessageLine, :MessageRuleId, :MessageData, :MessageSeverity)'

      phase_h_msg.each do |msg|
        msg['Message_Pattern'] = '' if msg['Message_Pattern'].blank? 
        msg['Message_Action'] = '' if msg['Message_Action'].blank?
        msg['Message_File'] = '' if msg['Message_File'].blank?
        msg['Message_Line'] = '' if msg['Message_Line'].blank?
        msg['Message_RuleId'] = '' if msg['Message_RuleId'].blank?
        msg['Message_Msg'] = '' if msg['Message_Msg'].blank?
        msg['Message_Data'] = '' if msg['Message_Data'].blank?
        msg['Message_Severity'] = 99 if msg['Message_Severity'].blank?

        begin
          insert_msg_sth = Events_Messages.new
          insert_msg_sth.event_id = event_id
          insert_msg_sth.h_message_pattern = msg['Message_Pattern']
          insert_msg_sth.h_message_action = msg['Message_Action']
          insert_msg_sth.h_message_ruleFile = msg['Message_File']
          insert_msg_sth.h_message_ruleLine = msg['Message_Line']
          insert_msg_sth.h_message_ruleId = msg['Message_RuleId']
          insert_msg_sth.h_message_ruleData = msg['Message_Data']
          insert_msg_sth.h_message_ruleSeverity = msg['Message_Severity']

          insert_msg_sth.save!

          msg_id = insert_msg_sth.msg_id

          # Insert message tag
          #if insertStatus == 0
            if msg['Message_Tag'].present? && msg['Message_Tag'].kind_of?( Array )

              #sql_messageTag = 'INSERT INTO `events_messages_tag` (`msg_id`, `h_message_tag`) VALUES (:msg_id, :tag)'

              msg['Message_Tag'].each do |tag|
                begin
                  insert_msgtag_sth = Events_Messages_Tag.new
                  insert_msgtag_sth.msg_id = msg_id
                  insert_msgtag_sth.h_message_tag = tag

                  insert_ruleMessage_sth.save!

                rescue 
                  response.headers['Status'] = '500';
                  abort( "Error (insert message tag)" )
                end
              end
            end

            #sql_ruleMessage = 'INSERT IGNORE INTO `rule_message` (`message_ruleId`, `message_ruleMsg`) VALUES (:MessageRuleId2, :MessageMsg)'

            begin
              insert_ruleMessage_sth = Rule_Message.new
              insert_ruleMessage_sth.message_ruleId = msg['Message_RuleId']
              insert_ruleMessage_sth.message_ruleMsg = msg['Message_Msg']

              insert_ruleMessage_sth.save!

            rescue
              response.headers['Status'] = '500';
              abort( "Error (insert rule message)" );
            end
          #end
        rescue
          response.headers['Status'] = '500';
          abort( "Error (insert events)" )
        end
      end
    end
  end #def

  def rtrim( str, rtrim_char )
	str.nil? ? nil : str.chomp( rtrim_char )
  end

  # Check a sensor login
  def sensorLogin(ip, loginpass64, login, pass)

    # convert remote address to long
    remote_addr_long = ip2long(ip);
    login_result = {}

    # sql = "SELECT sensor_id, name, IP, client_ip_via, client_ip_header FROM sensors WHERE status = 'Enabled' AND name LIKE :loginname AND password LIKE :password LIMIT 0 , 1";

    begin
      sensorData = Sensors.where( status: 'Enabled', name: login, password: pass ).take

	  return login_result if sensorData.blank?

      iprange                 = networkRange(sensorData.IP);
      sensor_id               = sensorData.sensor_id;
      sensor_name             = sensorData.name;
      sensor_client_ip_header = sensorData.client_ip_header;

      if remote_addr_long >= iprange['networklong'].to_i and remote_addr_long <= iprange['broadcastlong'].to_i or sensorData.IP.blank? 
        login_result['status']      = 1;
        login_result['sensor_id']   = sensor_id;
        login_result['sensor_name'] = sensor_name;
        login_result['sensor_client_ip_header'] = sensor_client_ip_header;
      else
        login_result['status'] = 0;
        login_result['msg'] = "User, IP or Password don't match";
      end
    rescue Exception => e
      response.headers['Status'] = '500'
      raise e
      abort e.message
    end

    return login_result
  end

  def networkRange( ip_add_range )
    if ( ip_result = ip_add_range.scan( /^([12]?\d{1,2}\.[12]?\d{1,2}\.[12]?\d{1,2}\.[12]?\d{1,2})(\/\d{1,2})?$/ ) ).present?
        ip_addr = ip_result[0][0]

        if ( ip_result[0][1].present? )
          cidr = str_replace("/", "", ip_result[0][1])
        else
          cidr = 32
        end

        if validateIP(ip_addr) and sanitize_int(cidr, min = '1', max = '32')

            subnet_mask = long2ip(-1 << (32 - cidr.to_i))
            ip          = ip2long(ip_addr)
            nm          = ip2long(subnet_mask)
            nw          = (ip & nm)
            bc          = nw | (~nm)

            iprange = {}

            iprange['ip']            = long2ip(ip)
            iprange['iplong']        = ip.to_s
            iprange['cidr']          = cidr
            iprange['netmask']       = long2ip(nm)
            iprange['network']       = long2ip(nw)
            iprange['networklong']   = nw.to_s
            iprange['broadcast']     = long2ip(bc)
            iprange['broadcastlong'] = ip2long(iprange['broadcast']).to_s
            iprange['hosts']         = (bc - nw + 1)
            iprange['range']         = long2ip(nw) + " -> " + long2ip(bc)

            return iprange
        else
            return false
        end
    else
        return false
    end
  end

  def validateIP(ip)
    if ip.present? and ip.scan( /^([12]?\d{1,2}\.[12]?\d{1,2}\.[12]?\d{1,2}\.[12]?\d{1,2})(\/\d{1,2})?$/ ).present?
        if ip2long(ip)
            valid = true
        elsif networkRange(ip)
            valid = true
        else
            valid = false
        end
    else
        valid = false
    end

    return valid
  end

  def sanitize_int(integer, min=0, max=0)
    int = integer.to_i

    if ( min.present? && int < min.to_i ) || ( max.present? && int > max.to_i )
        return false
    end

    int
  end

  def strstr_after( haystack, needle, case_insensitive = false)
    pos = false

    if case_insensitive
      pos = haystack.downcase.index( needle.downcase )
    else
      pos = haystack.index( needle )
    end

    if pos.present?
      return trim( trim( haystack[0, pos + needle.length] ), "\"" );
    end

    # Most likely false or null
    return pos;
  end

  def ip2long(ip)
    long = 0
    ip.split(/\./).each_with_index do |b, i|
      long += b.to_i << ( 8*i )
    end
    long
  end

  def long2ip(long)
    ip = []
    4.times do |i|
      ip.push(long.to_i & 255)
      long = long.to_i >> 8
    end
    ip.join(".")
  end

  def trim( string, chars = " " ) 
    chars = Regexp.escape(chars)
    string.gsub(/\A[#{chars}]+|[#{chars}]+\z/, "")
  end

  #Get the two letter country code
  def geoip_country_code_by_name( ip )
  	c = GeoIP.new('GeoIP.dat').country( ip )
  	return c.present? ? c.country_code2 : ''
  end

  def geoip_isp_by_name( ip )
  	c = GeoIP.new('GeoIPASNum.dat').asn( ip )
  	return c.present? ? c.isp : ''
  end

  # Get/Set the Web Hostname ID from/on database
  def getWebHostID(host)
    host = host.downcase;

    #$sql = 'SELECT `host_id` FROM `events_hostname` WHERE `hostname` = :host';

    begin
      ehn = Events_Hostname.find_by( hostname: host )
      if ( ehn.blank? )
      	ehn = Events_Hostname.create( hostname: host )
      end

      webHostID = ehn.host_id
    rescue
      response.headers['Status'] = "500"
      abort()
	  end

    webHostID;
  end

  def gzcompress(str)
    return ActiveSupport::Gzip.compress(str)
  end


  def echo_init
  	@outputbuffer = ''
  end

  def echo( str )
  	#@outputbuffer.concat( str.to_s )
  	@outputbuffer.concat( str.inspect )
  end

  def echo_flush
  	render :text => @outputbuffer;
  	@outputbuffer = "";
  end

end