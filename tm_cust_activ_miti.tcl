::cisco::eem::event_register_timer cron name crontimer2 cron_entry $_cron_entry maxrun 240
#------------------------------------------------------------------
# EEM policy that will periodically check if interfaces with description 
# "_interface_descriptor" are under load the execute a cli command to start 
# mitigation and email an alert.
#
# Sept 2018, Skylark
#
#------------------------------------------------------------------
### The following EEM environment variables are used:
###
### _cron_entry                        - A CRON specification that determines 
###                                      when the policy will run. 
###                                      Example: _cron_entry */2 * * * *
### _log_file                          - Output is appended to the specified file 
###                                      with a timestamp added. Only use for debuging
###                                      Example: _log_file disk0:/my_file.log
### _email_server                      - A Simple Mail Transfer Protocol (SMTP)
###                                      mail server used to send e-mail.
###                                      Example: _email_server mailserver.example.com
### _email_from                        - The address from which e-mail is sent.
###
### _email_to                          - The address to which the e-mail is sent.
###
### _email_source                      - The ip address from which the e-mail is sent.
###                                      Example: _email_source MgmtEth0
### _domainname                        - Value not needed but sendmail will not run
###                                      without it.
###                                      Example: _domainname x.x 
### _interface_descriptor              - descriptor used to identify the interface(s)
###                                      Example: _interface_descriptor Peering
### _rxload_threshold                  - Level of traffic that triggers an alarm
###                                      (40mbps = 1 on a 10G interface)
###                                      Example: _rxload_threshold 4
### _mitigation_threshold              - The number of interfaces in alarm state 
###                                      need to start mitigation
###                                      Example: _mitigation_threshold 2
### _CAM_policy                        - AUTO = monitorin for DDOS load 
###                                      SET = turn on CAM and desiable Policy (ro)
###                                      OFF = diabled (manual)
###                                      RESETS = turn off CAM and revert to AUTO
###                                      Example: _CAM_policy AUTO

#------------------- "Start of the Policy"------------------
namespace import ::cisco::eem::*
namespace import ::cisco::lib::*


#------------------- "Check if varables are set"-------------------

if {![info exists _cron_entry]} {
    action_syslog msg  "Sript cannot be run: variable _cron_entry has not been set"
    return
}
if {![info exists _CAM_policy]} {
    action_syslog msg  "Sript cannot be run: variable _CAM_policy has not been set"
    return
}

# Policy will not run without an eamil server unless a log file has been defined
if {![info exists _log_file]} {
  if {![info exists _email_server]} {
      action_syslog msg  "Policy cannot be run: variable _email_server has not been set"
      return
  }
}

# Check if any value is missing for emails if an email server has been confiured
if {[info exists _email_server]} {
  if {![info exists _email_from]} {
      action_syslog msg  "Policy cannot be run: variable _email_from has not been set"
      return 
  }
  if {![info exists _email_to]} {
      action_syslog msg  "Policy cannot be run: variable _email_to has not been set"
      return
  }
  if {![info exists _email_cc]} {
      set _email_cc ""
  }
  if {![info exists _domainname]} {
      action_syslog msg  "Policy cannot be run: variable _domainname has not been set"
      return
  }
}

if {![info exists _interface_descriptor]} {
    action_syslog msg  "Policy cannot be run: variable _domainname has not been set"
    return
}

if {![info exists _rxload_threshold]} {
    action_syslog msg  "Policy cannot be run: variable _rxload_threshold has not been set"
    return
}

if {![info exists _mitigation_threshold]} {
    action_syslog msg  "Policy cannot be run: variable _mitigation_threshold has not been set"
    return
}

#------------------- "Check CAM status"-------------------


if {$_CAM_policy == "OFF" } {
      return
}
if {$_CAM_policy == "SET" } {
      return
}

#------------------- "Processes"-------------------

# comand to RUN in CLI
proc process_run { cmd } {
    global errorInfo
    
    if [catch {cli_open} result] {
      error "Failed to open CLI session: '$result'" $errorInfo
    } else {
      array set cli $result
    }  

    if [catch {cli_exec $cli(fd) $cmd} result] {
          error "Failed to execute the command '$cmd': '$result'" $errorInfo
    } else {
    append results $result
    }
        
    catch {cli_close $cli(fd) $cli(tty_id)}
    return $results
}

# comands to CHANGE  in CLI
proc process_config { cmds } {
    global errorInfo

    if { [catch {cli_open} result] } {
      error "Failed to open CLI session: '$result'" $errorInfo
    } else {
      array set cli $result
    }  

    
    if { [catch {cli_exec $cli(fd) "Configure Terminal"} result] } {
      error "Failed to enter configuration mode: '$result'" $errorInfo
    }
    
    foreach cmd $cmds {
        if { [catch {cli_exec $cli(fd) $cmd} result] } {
          error "Failed to execute the command '$cmd': '$result'" $errorInfo
        } else {
        append results $result "\n"
        }

    }
    if { [catch {cli_exec $cli(fd) "Commit"} result] } {
      error "Failed to Commit changes: '$result'" $errorInfo
    }
    
    catch {cli_close $cli(fd) $cli(tty_id)}
    return $results
}

# write a LOG entry
proc write_log { mgs } {
  global errorInfo
  global _log_file
  if {[info exists _log_file]} {
    # attach output to file
    if [catch {open $_log_file a+} result] {
        error $result
    }
    set fileD $result
    puts $fileD $mgs
    close $fileD
  }
}

# send an email
proc send_email { subj mgs } {
  global errorInfo
  global _email_server
  global _email_from
  global _email_to
  global _email_cc
  global _email_source
  if {[info exists _email_server]} {
    set routername [info hostname]
    if {[string match "" $routername]} {
      error "Host name is not configured"
    }
    set email {Mailservername: $_email_server
      From: $_email_from
      To: $_email_to
      Cc: $_email_cc
      Sourceaddr: $_email_source
      Subject: From router $routername: $subj 

      $mgs
    }
    if [catch {smtp_send_email $email} result] {
      action_syslog msg "$result"
    }
  }
}


##################### "STOP mitigation" ##################### 

if {$_CAM_policy == "RESET" } {
  set time_now [clock seconds]
  set time_now [clock format $time_now -format "%T %Z %a %b %d %Y"]
  set mgs "$time_now MITIGATION alert: Manual reset triggered, routes going back to normal"
  set subj "Mitigation Alert (CAM RESET)"
  
  # log alert event
  write_log $mgs

  # alert email sent
  send_email $subj $mgs

  # command excuted: 
  process_config {
    "#command 1"
    "#command 2"
    "event manager environment _CAM_policy AUTO"
  }
  action_syslog msg "MITIGATION alert: Manual reset triggered, routes going back to normal"
  return

# Stop Policy if CAM is alredy active
} elseif {$_CAM_policy != "AUTO" } {
      action_syslog msg "Sript cannot be run: CAM settings invalid (_CAM_policy $_CAM_policy)"
      return
}

##################### "START mitigation" ##################### 

# reset counters
set rxload "0"
set rxload "0"
set mitigation "0"
set over ""


#------------------- "Find interfaces"-------------------

set int_list [process_run "show interfaces description  | inc $_interface_descriptor | inc up"]

regsub {.*?\n} $int_list "" int_list
regsub {.*?\n} $int_list "" int_list
regsub {.*?\n} $int_list "" int_list
regsub -all "RP.*?$" $int_list "" int_list
regsub -all "up.*?\n" $int_list "\n" int_list


#------------------- "Check RXload"-------------------

foreach i $int_list {
  set int_load [process_run "show interface $i | inc rxload"]
  
  regexp {rxload ([0-9]*)} $int_load rxload
  regsub -all {[a-z]} $rxload "" rxload

  if { $rxload >= $_rxload_threshold } { 
      incr mitigation
      append over "Interface: $i over threshold, rxload: $rxload\n"    
  }
}


#------------------- "Start mitigation"-------------------

if { $mitigation >= $_mitigation_threshold } {
  set time_now [clock seconds]
  set time_now [clock format $time_now -format "%T %Z %a %b %d %Y"]
  set mgs "$time_now MITIGATION alert: Possible DDOS attack under way, $mitigation interfaces over acceptable load, activating mitigation"
  set subj "Mitigation Alert (CAM SET)"
  append mgs "\n"
  append mgs $over
  
  # log alert event
  write_log $mgs

  # alert email sent
  send_email $subj $mgs
  
  # command excuted: 
  process_config {
    "#command 1"
    "#command 2"
    "event manager environment _CAM_policy SET"
  }
  action_syslog msg "MITIGATION alert: Possible DDOS attack under way, $mitigation interfaces over acceptable load, activating mitigation"
}