#!/usr/bin/ruby
#
# Apache2 log analyzer to count unique ips and number of queries
# This script is used to find the unique ips in an apache2 access.log
# and count the number of queries for each ip, the number of errors served.
#
#   ApacheLogAnalyzer: Analyzer for a log file given the full or relative path
#

class ApacheLogAnalyzer 
  def initialize
    @total_hits_by_ip = Hash.new(0)
    @total_hits_per_url = Hash.new(0)
    @error_count = 0
  end
 
 # Analyzes a log file provided the full or relative path
 #
 # Args:
 # - file_name: string -- Full or relative path to a log file
 #
 
  def analyze(file_name)
  # Regex to match a single octet of an IPv4 address
    octet = /\d{,2}|1\d{2}|2[0-4]\d|25[0-5]/
	# Since an IPv4 address is made of four octets we will string them together
	# to match the full IPv4 address
    ip_regex = /^#{octet}\.#{octet}\.#{octet}\.#{octet}/
    url_regex = /[a-zA-Z0-9]+.html/
	# Regex to match an alphanumeric url ending with .html
	
	# Reads in the file line by line using a loop
	# Matches the various regex (IP Address, URL, and 404 Error)
	# and pass them to the count_hits function to be counted
    File.readlines('/var/log/apache2/access.log').each do |line|
      ip = line.scan(ip_regex).first
      ip = line.scan(ip_regex)[0]
      url = url_regex.match(line).to_s
      error = line.include?("404")
      count_hits(ip, url, error) unless url == ""
    end
    print_hits
  end

  private
  #
  # Args:
  # - ip: string -- IP address responsible for the logged entry
  # - url: string -- URL queried for the logged entry
  # - error: bool -- Whether or not the log entry contained a 404 error
  #
  def count_hits(ip, url, error)
  # Associate the request with the IP Address
	# Associate the request with the url requested
	# Keep track of the total number of 404 errors served
    @total_hits_by_ip[ip] += 1
    @total_hits_per_url[url] += 1
    @error_count += 1 if error
  end
  
  # Print the number of queries for each ip in the total
  #
  
  def print_hits
    print_string = 'IP: %s, Total Hits: %s'
    @total_hits_by_ip.sort.each do |ip, total_hits|
      puts sprintf(print_string, ip, total_hits)
    end
    url_print_string = 'URL: %s, Number of Hits: %s'
    @total_hits_per_url.sort.each do |url, url_hits|
      puts sprintf(url_print_string, url, url_hits)
    end
    puts sprintf('Total Errors: %s', @error_count)
  end
end

def usage
  puts "No log files passed, please pass at least one log file.\n\n"
  puts "USAGE: #{$PROGRAM_NAME} file1 [file2 ...]\n\n"
  puts "Analyzes apache2 log files for unique IP addresses and unique URLs."
end

def main
  if ARGV.empty?
    usage
    exit(1)
  end
  ARGV.each do |file_name|
    log_analyzer = ApacheLogAnalyzer.new
    log_analyzer.analyze(file_name)
  end
end

if __FILE__ == $PROGRAM_NAME
  main
end