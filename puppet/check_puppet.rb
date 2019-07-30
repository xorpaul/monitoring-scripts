#!/opt/puppetlabs/puppet/bin/ruby

# A simple nagios check that should be run as root
# perhaps under the mcollective NRPE plugin and
# can check when the last run was done of puppet.
# It can also check fail counts and skip machines
# that are not enabled
#
# The script will use the puppet last_run_summary.yaml
# file to determine when last Puppet ran else the age
# of the statefile.
#
# 19/12/2013 --- Change to lock files and handling of a puppet agent in a disabled state (WARNING)
#            *** These changes are made to work with puppet 3.X and MAY cause some issues with 2.x users
#            *** The script should still continue to work for 2.x, but may not handle the lockfiles correctly
#            *** and will require the proper arguments to match 2.x filename.
require 'optparse'
require 'yaml'
require 'socket'
require 'openssl'
require 'puppet'

statedir_puppet_3 = "/var/lib/puppet/state"
statedir_puppet_4 = "/opt/puppetlabs/puppet/cache/state"
File.directory?(statedir_puppet_4) ? statedir = statedir_puppet_4 : statedir = statedir_puppet_3
conffile_puppet_2 = "/etc/puppet/puppet.conf"
conffile_puppet_4 = "/etc/puppetlabs/puppet/puppet.conf"
File.exists?(conffile_puppet_4) ? conffile = conffile_puppet_4 : conffile = conffile_puppet_2
agent_lockfile = statedir + "/agent_catalog_run.lock"
agent_disabled_lockfile = statedir + "/agent_disabled.lock"
statefile = statedir + "/state.yaml"
summaryfile = statedir + "/last_run_summary.yaml"
reportfile = statedir + "/last_run_report.yaml"
enabled = true
running = false
lastrun_failed = false
lastrun = 0
failcount_resources = 0
failcount_events = 0
warn = 0
crit = 0
total_failure = false
enabled_only = false
failures = false
disable_perfdata = false
disable_multiline_failed_resources_output = false
disabled_message = "reason not specified"
report_puppetserver = false
check_clientcert_age = false
enable_check_mk_html_breaks = false

opt = OptionParser.new

opt.on("--critical [CRIT]", "-c", Integer, "Critical threshold, time or failed resources") do |f|
    crit = f.to_i
end

opt.on("--warn [WARN]", "-w", Integer, "Warning threshold, time or failed resources") do |f|
    warn = f.to_i
end

opt.on("--check-failures", "-f", "Check for failed resources instead of time since run") do |f|
    failures = true
end

opt.on("--report-puppetserver", "-r", "Output the used Puppetserver service name from the Puppet agent config") do |f|
    report_puppetserver = true
end

opt.on("--check-clientcert-age", "-a", "Check for expiring Puppet client certificate") do |f|
    check_clientcert_age = true
end

opt.on("--only-enabled", "-e", "Only alert if Puppet is enabled") do |f|
    enabled_only = true
end

opt.on("--state-dir [FILE]", "Location of the state directory containing lock and state files, default #{statedir}, will change location of the files") do |f|
    statedir = f
    agent_lockfile = statedir + "/agent_catalog_run.lock"
    agent_disabled_lockfile = statedir + "/agent_disabled.lock"
    statefile = statedir + "/state.yaml"
    summaryfile = statedir + "/last_run_summary.yaml"
    reportfile = statedir + "/last_run_report.yaml"
end

opt.on("--agent-lock-file [FILE]", "-l", "Location of the agent run lock file, default #{agent_lockfile}") do |f|
    agent_lockfile = f
end

opt.on("--agent-disabled-lock-file [FILE]", "-d", "Location of the agent disabled lock file, default #{agent_disabled_lockfile}") do |f|
    agent_disabled_lockfile = f
end

opt.on("--state-file [FILE]", "-t", "Location of the state file, default #{statefile}") do |f|
    statefile = f
end

opt.on("--summary-file [FILE]", "-s", "Location of the summary file, default #{summaryfile}") do |f|
    summaryfile = f
end

opt.on("--report-file [FILE]", "-s", "Location of the report file, default #{reportfile}") do |f|
    reportfile = f
end

opt.on("--disable-perfdata", "-x", "Disable performance data output") do |f|
    disable_perfdata = f
end

opt.on("--disable-multiline-failed-resources-output", "-m", "Disable printing the failed Puppet resource messages in the multiline output") do |f|
    disable_multiline_failed_resources_output = f
end

opt.on("--enable-checkmk-html-breaks", "-b", "add </br> html to the multiline newline output") do |f|
    enable_check_mk_html_breaks = true
end

opt.parse!

if warn == 0 || crit == 0
    puts "Please specify a warning and critical level"
    exit 3
end

if File.exists?(agent_lockfile)
    if File::Stat.new(agent_lockfile).zero?
       enabled = false
    else
       running = true
    end
end

if File.exists?(agent_disabled_lockfile)
    enabled = false
    disabled_message = File.open(agent_disabled_lockfile, 'r').read.gsub(/.*\"(.*)\"\}/, '\1') || "reason not specified"
end


lastrun = File.stat(statefile).mtime.to_i if File.exists?(statefile)

def report_failed_resources(reportfile, enable_check_mk_html_breaks, disable_multiline_failed_resources_output)
  return "", "" if disable_multiline_failed_resources_output
  failed_resources = []
  failed_catalog = false
  long_output_failed_resources = ""
  begin
    report = YAML.load_file(reportfile)
    report.resource_statuses.each do |resource_name,resource|
      if resource.failed
        failed_resources << resource_name
        single_long_output_failed_resources = "\nResource #{resource_name} failed:\n\t#{resource.events[0].message if resource.events[0]}"
        single_long_output_failed_resources = single_long_output_failed_resources.gsub("\n","</br>\n") if enable_check_mk_html_breaks
        long_output_failed_resources += single_long_output_failed_resources
      end
    end
    report.logs.each do |resource|
      if (resource.level).match(/err/)
        if (resource.message).match(/Error 500 on SERVER/)
          failed_catalog = true
        end
      end
    end

  rescue => e
    puts "Unable to report the failed resource messages, because:\n#{e}"
  end

  failed_resources_text = "Failed Puppet resources: "
  failed_resources_text += "Error 500 on SERVER " if failed_catalog
  failed_resources_text += "<b><font color='red'>" if enable_check_mk_html_breaks
  failed_resources_text += failed_resources.join(" ")
  failed_resources_text += "</font></b>" if enable_check_mk_html_breaks
  failed_resources_text = "There are #{failed_resources.size} failed Puppet resources." if failed_resources.size > 10

  return failed_resources_text+" ", long_output_failed_resources
end

unless File.readable?(summaryfile)
    puts "UNKNOWN: Summary file not found or not readable. Check #{summaryfile}"
    exit 3
else
    begin
        summary = YAML.load_file(summaryfile)
        lastrun = summary["time"]["last_run"]
        time = summary["time"]
        begin
          changes = summary["changes"]["total"]
        rescue
          total_failure = true
        end


        # machines that outright failed to run like on missing dependencies
        # are treated as huge failures.  The yaml file will be valid but
        # it wont have anything but last_run in it
        unless summary.include?("events")
            failcount_resources = 99
            failcount_events = 99
            total_failure = true
        else
            # and unless there are failures, the events hash just wont have the failure count
            failcount_resources = summary["resources"]["failed"] || 0
            failcount_events = summary["events"]["failure"] || 0
        end
    rescue
        failcount_resources = 0
        failcount_events = 0
        summary = nil
    end
end

# machines with could not retrieve catalog from remote server errors, do report without this as OK
unless File.readable?(reportfile)
    puts "UNKNOWN: report file not found or not readable. Check #{reportfile}"
    exit 3
else
  if File.open(reportfile).grep(/^status: failed/).size > 0
      total_failure = true
    end
end

time_since_last_run = Time.now.to_i - lastrun

time_since_last_run_string = "#{time_since_last_run} seconds ago"
if time_since_last_run >= 3600
  time_since_last_run_string = "#{time_since_last_run / 60 / 60} hours ago at #{Time.at(Time.now - time_since_last_run).utc.strftime('%R:%S')} UTC"
elsif time_since_last_run >= 60
  time_since_last_run_string = "#{time_since_last_run / 60} minutes ago"
end

if disable_perfdata
  perfdata_time = ""
else
  perfdata_time = "|time_since_last_run=#{time_since_last_run}s;#{warn};#{crit};0 failed_resources=#{failcount_resources};;;0 failed_events=#{failcount_events};;;0"
  time.each {|k,v| perfdata_time += " run_time_#{k}=#{((v*100).round() / 100.0).round()}s" if k != 'last_run'}
  if changes
    perfdata_time += " total_changes=#{changes};;;0"
  else
    perfdata_time += ' total_changes=0;;;0'
  end
end

used_puppetserver = ""
if report_puppetserver and File.exists?(conffile)
    used_puppetserver = " Used Puppetserver: "
    used_puppetserver += File.open(conffile, 'r').read.split("\n").grep(/^\s*server/).join().split('=')[1].strip() || "N/A"
end

if check_clientcert_age
  os_fqdn = Socket.gethostbyname(Socket.gethostname).first
  certfile_puppet_2 = "/var/lib/puppet/ssl/certs/#{os_fqdn}.pem"
  certfile_puppet_4 = "/etc/puppetlabs/puppet/ssl/certs/#{os_fqdn}.pem"
  File.exists?(certfile_puppet_4) ? certfile = certfile_puppet_4 : certfile = certfile_puppet_2
  if File.readable?(certfile)
    certificate = OpenSSL::X509::Certificate.new(File.read(certfile))
    if Time.now + 60*60*24*30 >= certificate.not_after
      puts "CRITICAL: Puppet client certificate #{certfile} will expire in less than 30 days at #{certificate.not_after}!"
      exit 2
    end
  end
end

unless failures
    if enabled_only && enabled == false
        puts "OK: Puppet is currently disabled, not alerting. Last run #{time_since_last_run_string} with #{failcount_resources} failed resources #{failcount_events} failed events. Disabled with reason: #{disabled_message}#{used_puppetserver}#{perfdata_time}"
        exit 0
    end

    if total_failure
        failed_resources, long_output_failed_resources = report_failed_resources(reportfile, enable_check_mk_html_breaks, disable_multiline_failed_resources_output)
        puts "CRITICAL: #{failed_resources}Last run #{time_since_last_run_string}#{used_puppetserver}#{perfdata_time}\n#{long_output_failed_resources}"
        exit 2
    elsif time_since_last_run >= crit
        puts "CRITICAL: last run #{time_since_last_run_string}, expected < #{crit}s#{used_puppetserver}#{perfdata_time}"
        exit 2

    elsif time_since_last_run >= warn
        puts "WARNING: last run #{time_since_last_run_string}, expected < #{warn}s#{used_puppetserver}#{perfdata_time}"
        exit 1

    else
        if enabled
            puts "OK: last run #{time_since_last_run_string} with #{failcount_resources} failed resources #{failcount_events} failed events and currently enabled#{used_puppetserver}#{perfdata_time}"
        else
            puts "WARNING: last run #{time_since_last_run_string} with #{failcount_resources} failed resources #{failcount_events} failed events and currently disabled with reason: #{disabled_message}#{used_puppetserver}#{perfdata_time}"
            exit 1
         end

        exit 0
    end
else
    if enabled_only && enabled == false
        puts "OK: Puppet is currently disabled, not alerting. Last run #{time_since_last_run_string} with #{failcount_resources} failed resources #{failcount_events} failed events. Disabled with reason: #{disabled_message}#{used_puppetserver}#{perfdata_time}"
        exit 0
    end

    if total_failure
        failed_resources, long_output_failed_resources = report_failed_resources(reportfile, enable_check_mk_html_breaks, disable_multiline_failed_resources_output)
        puts "CRITICAL: #{failed_resources}Last run #{time_since_last_run_string}#{used_puppetserver}#{perfdata_time}\n#{long_output_failed_resources}"
        exit 2
    elsif failcount_resources >= crit
        puts "CRITICAL: Puppet last ran had #{failcount_resources} failed resources #{failcount_events} failed events, expected < #{crit}#{used_puppetserver}#{perfdata_time}"
        exit 2

    elsif failcount_resources >= warn
        puts "WARNING: Puppet last ran had #{failcount_resources} failed resources #{failcount_events} failed events, expected < #{warn}#{used_puppetserver}#{perfdata_time}"
        exit 1

    else
        if enabled
            puts "OK: last run #{time_since_last_run_string} with #{failcount_resources} failed resources #{failcount_events} failed events and currently enabled#{used_puppetserver}#{perfdata_time}\n#{multiline}"
        else
            puts "WARNING: last run #{time_since_last_run_string} with #{failcount_resources} failed resources #{failcount_events} failed events and currently disabled with reason: #{disabled_message}#{used_puppetserver}#{perfdata_time}"
            exit 1
        end

        exit 0
    end
end
