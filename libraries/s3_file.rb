# coding: utf-8
#
# Author:: Christopher Peplin (<peplin@bueda.com>)
# Author:: Ivan Porto Carrero (<ivan@mojolly.com>)
# Author:: Paul Poulain (<paul.poulain@mirada.tv>)
# Copyright:: Copyright (c) 2010 Bueda, Inc.
# Copyright:: Copyright (c) 2011 Mojolly Ltd.
# Copyright:: Copyright (c) 2011 mirada plc.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require 'digest/sha1'
require 'openssl'
require 'cgi'
require 'base64'
require "net/http"
require "net/https"
require 'tempfile'

## The S3Sign class generates signed URLs for Amazon S3
class S3Sign

  def initialize(aws_access_key_id, aws_secret_access_key)
    @aws_access_key_id = aws_access_key_id
    @aws_secret_access_key = aws_secret_access_key
  end

  # builds the canonical string for signing.
  def canonical_string(method, path, headers={}, expires=nil)
    interesting_headers = {}
    headers.each do |key, value|
      lk = key.downcase
      if lk == 'content-md5' or lk == 'content-type' or lk == 'date' or lk =~ /^x-amz-/
        interesting_headers[lk] = value.to_s.strip
      end
    end

    # these fields get empty strings if they don't exist.
    interesting_headers['content-type'] ||= ''
    interesting_headers['content-md5'] ||= ''
    # just in case someone used this.  it's not necessary in this lib.
    interesting_headers['date'] = '' if interesting_headers.has_key? 'x-amz-date'
    # if you're using expires for query string auth, then it trumps date (and x-amz-date)
    interesting_headers['date'] = expires if not expires.nil?

    buf = "#{method}\n"
    interesting_headers.sort { |a, b| a[0] <=> b[0] }.each do |key, value|
      buf << ( key =~ /^x-amz-/ ? "#{key}:#{value}\n" : "#{value}\n" )
    end
    # ignore everything after the question mark...
    buf << path.gsub(/\?.*$/, '')
    # ...unless there is an acl or torrent parameter
    if    path =~ /[&?]acl($|&|=)/     then buf << '?acl'
    elsif path =~ /[&?]torrent($|&|=)/ then buf << '?torrent'
    end
    return buf
  end

  def hmac_sha1_digest(key, str)
    OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, key, str)
  end

  # encodes the given string with the aws_secret_access_key, by taking the
  # hmac-sha1 sum, and then base64 encoding it. then url-encodes for query string use
  def encode(str)
    CGI::escape(Base64.encode64(hmac_sha1_digest(@aws_secret_access_key, str)).strip)
  end

  # generate a url to put a file onto S3
  def put(bucket, key, expires_in=0, headers={})
    return generate_url('PUT', "/#{bucket}/#{CGI::escape key}", expires_in, headers)
  end

  # generate a url to put a file onto S3
  def get(bucket, key, expires_in=0, headers={})
    return generate_url('GET', "/#{bucket}/#{CGI::escape key}", expires_in, headers)
  end

  # generate a url with the appropriate query string authentication parameters set.
  def generate_url(method, path, expires_in, headers)
    #log "path is #{path}"
    expires = expires_in.nil? ? 0 : Time.now.to_i + expires_in.to_i
    canonical_string = canonical_string(method, path, headers, expires)
    encoded_canonical = encode(canonical_string)
    arg_sep = path.index('?') ? '&' : '?'
    return path + arg_sep + "Signature=#{encoded_canonical}&" + 
           "Expires=#{expires}&AWSAccessKeyId=#{@aws_access_key_id}"
  end

end

class Chef
  class Provider
    class S3AwareRemoteFile < Chef::Provider::RemoteFile

      def action_create
        # Only do the S3 logic if it looks like an S3 URL (case insensitive)
        if @new_resource.source.match(/^s3/i)
          Chef::Log.debug("Checking #{@new_resource} for changes")

          if current_resource_matches_target_checksum?
            Chef::Log.debug("File #{@new_resource} checksum matches target checksum (#{@new_resource.checksum}), not updating")
          else
            Chef::Log.debug("File #{@current_resource} checksum didn't match target checksum (#{@new_resource.checksum}), updating")
            fetch_from_s3(@new_resource.source) do |raw_file|
              if matches_current_checksum?(raw_file)
                Chef::Log.debug "#{@new_resource}: Target and Source checksums are the same, taking no action"
              else
                backup_new_resource
                Chef::Log.debug "copying remote file from origin #{raw_file.path} to destination #{@new_resource.path}"
                FileUtils.cp raw_file.path, @new_resource.path
                @new_resource.updated_by_last_action true
              end
            end
          end
          enforce_ownership_and_permissions

          @new_resource.updated
        else 
          # Appears not to be an S3 URL. Delegate to the superclass.
          self.class.superclass.instance_method("action_create").bind(self).call
        end
      end

      def fetch_from_s3(source)
        begin
          region, bucket, key = URI.split(source).compact
          key = key[1..-1]
          expires = @new_resource.expires || 30
          s3 = S3Sign.new(@new_resource.access_key_id, @new_resource.secret_access_key)
          access_key = @new_resource.access_key_id
          secret_key = @new_resource.secret_access_key
          headers = @new_resource.headers || {}
          Chef::Log.debug("Downloading #{key} from S3 bucket #{bucket}")
          file = Tempfile.new("chef-s3-file")
          host = "#{region||"s3"}.amazonaws.com"
          Chef::Log.debug("Connecting to s3 host: #{host}:443")
          http_client = Net::HTTP.new(host, 443)
          http_client.use_ssl = true
          http_client.verify_mode = OpenSSL::SSL::VERIFY_NONE
          http_client.start do |http|
            pth = s3.get(bucket, key, expires, headers)
            Chef::Log.debug("Requesting #{pth}")
            http.request_get(pth) do |res|
              res.read_body do |chunk|
                file.write chunk
              end
            end
          end
          Chef::Log.debug("File #{key} is #{file.size} bytes on disk")
    
          # If the file size is less than 1k, check the file didn't contain any errors (it would fail the checksum test if configured
          # but a helpful error message would be nice)
          # Error messages can look like this:
          #   <?xml version="1.0" encoding="UTF-8"?>
          #   <Error><Code>AccessDenied</Code><Message>Access Denied</Message><RequestId>FCD8E2E772C5583B</RequestId><HostId>jBnN9pZOHGb9xov9mbXhfsPKReFUjYZg9A240scOGQkSa2S/ekGMl2JZCeoXuEie</HostId></Error>
          # or maybe this:
          #   <?xml version="1.0" encoding="UTF-8"?>
          #   <Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>not_here/Test.txtd</Key><RequestId>6BA9A12E179BD984</RequestId><HostId>K4Osi2DIoQ8I41RpHRqgp0doVMBgTpSorKSl+zFQQXJJWHyBv5YfHnFkH9DBQGbK</HostId></Error>
          if file.size < 1000
            file.rewind
            fileContents = file.read
            match = fileContents.match(/<Error><Code>(.*)<\/Code><Message>(.*)<\/Message>.*<\/Error>/)
            Chef::Log.warn("Match #{match}")
            if match
              Chef::Log.error("Got an S3 error downloading the file: #{match[1]} - #{match[2]}")
              Chef::Log.error("Response: #{fileContents}")
              raise "Error downloading file from S3: #{match[1]} (#{match[2]})"
              nil
            end
          end

          begin
            yield file
          ensure
            file.close
          end     
        rescue URI::InvalidURIError
          Chef::Log.warn("Expected an S3 URL but found #{source}")
          nil
        end
      end
    end
  end
end

class Chef
  class Resource
    class S3AwareRemoteFile < Chef::Resource::RemoteFile
      def initialize(name, run_context=nil)
        super
        @resource_name = :s3_aware_remote_file
      end

      def provider
        Chef::Provider::S3AwareRemoteFile
      end

      def access_key_id(args=nil)
        set_or_return(
          :access_key_id,
          args,
          :kind_of => String
        )
      end
        
      def secret_access_key(args=nil)
        set_or_return(
          :secret_access_key,
          args,
          :kind_of => String
        )
      end

      def headers(args={})
        set_or_return(
          :headers,
          args,
          :kind_of => Hash
        )
      end

      def expires(args=30)
        set_or_return(
          :expires,
          args,
          :kind_of => Integer
        )
      end
    end 
  end
end

# vim: set si ts=2 sw=2 sts=2 et:
