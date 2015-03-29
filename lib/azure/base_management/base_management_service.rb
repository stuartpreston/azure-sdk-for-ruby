#-------------------------------------------------------------------------
# Copyright 2013 Microsoft Open Technologies, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#--------------------------------------------------------------------------
require 'rubygems'
require 'nokogiri'
require 'base64'
require 'openssl'
require 'uri'
require 'rexml/document'
require 'azure/base_management/serialization'
require 'azure/base_management/location'
require 'azure/base_management/affinity_group'

include Azure::BaseManagement
include Azure::Core::Utility
Loggerx = Azure::Core::Logger

module Azure
  module BaseManagement
    class BaseManagementService
      def initialize
        validate_configuration
        certificate_key, private_key = read_management_certificate(Azure.config.management_certificate)
        Azure.configure do |config|
          config.http_certificate_key = certificate_key
          config.http_private_key = private_key
        end
      end

      def validate_configuration
        subs_id = Azure.config.subscription_id
        error_message = 'Subscription ID not valid.'
        raise error_message if subs_id.nil? || subs_id.empty?

        m_ep = Azure.config.management_endpoint
        error_message = 'Management endpoint not valid.'
        raise error_message if m_ep.nil? || m_ep.empty?

        m_cert = Azure.config.management_certificate
        if m_cert.is_a?(Hash)
           error_message = "Management certificate hash #{m_cert} does not have key :type!  If specifying a hash, you must specify :type => <:pem, :pfx or :publishsettings>!"
           raise error_message unless m_cert.has_key?(:type) && %w(pem pfx publishsettings).include?(m_cert[:type].to_s)

           error_message = "Management certificate hash #{m_cert} does not have the certificate data!  If specifying a hash, you must specify either :data => String, :io => <IO object> or :path => <path>!"
           raise error_message unless [ :data, :io, :path ].any? { |k| m_cert.has_key?(k) }

           unexpected_keys = m_cert.keys - [ :type, :data, :io, :path ]
           error_message = "Management certificate hash #{m_cert} has unexpected keys #{unexpected_keys.join(", ")}!  Only :type, :data, :io and :path are accepted values when specifying a hash."
           raise error_message unless unexpected_keys.empty?

           if m_cert[:data]
             error_message= "Management certificate :data in #{m_cert} is not a String!  Must be a String."
             raise error_message unless m_cert[:data].is_a?(String)
           end
           if m_cert[:io]
             error_message= "Management certificate :io in #{m_cert} is not an IO object!  Must be an IO object."
             raise error_message unless m_cert[:io].is_a?(IO)
           end
           if m_cert[:path]
             error_message= "Management certificate :path in #{m_cert} is not a String!  Must be a String."
             raise error_message unless m_cert[:path].is_a?(String)
             unless m_cert[:data] || m_cert[:io] # :path is only used to print information out if data or IO is there
               error_message = "Could not read from file '#{m_cert[:path]}'."
               raise error_message unless test('r', m_cert[:data])
             end
           end

        else
           m_cert_ext = File.ext(m_cert)
           error_message = "Management certificate path '#{m_cert}' must have extension .pem, .pfx or .publishsettings"
           raise error_message unless %w(pem pfx publishsettings).include?(m_cert_ext)

           error_message = "Could not read from file '#{m_cert}'."
           raise error_message unless test('r', m_cert)
        end

      end

      # Public: Gets a list of regional data center locations from the server
      #
      # Returns an array of Azure::BaseManagement::Location objects
      def list_locations
        request = ManagementHttpRequest.new(:get, '/locations')
        response = request.call
        Serialization.locations_from_xml(response)
      end

      # Public: Gets a lists the affinity groups associated with
      # the specified subscription.
      #
      # See http://msdn.microsoft.com/en-us/library/windowsazure/ee460797.aspx
      #
      # Returns an array of Azure::BaseManagement::AffinityGroup objects
      def list_affinity_groups
        request_path = '/affinitygroups'
        request = ManagementHttpRequest.new(:get, request_path, nil)
        response = request.call
        Serialization.affinity_groups_from_xml(response)
      end

      # Public: Creates a new affinity group for the specified subscription.
      #
      # ==== Attributes
      #
      # * +name+           - String. Affinity Group name.
      # * +location+       - String. The location where the affinity group will
      # be created.
      # * +label+         - String. Name for the affinity specified as a
      # base-64 encoded string.
      #
      # ==== Options
      #
      # Accepted key/value pairs are:
      # * +:description+   - String. A description for the affinity group.
      # (optional)
      #
      # See http://msdn.microsoft.com/en-us/library/windowsazure/gg715317.aspx
      #
      # Returns:  None
      def create_affinity_group(name, location, label, options = {})
        if name.nil? || name.strip.empty?
          raise 'Affinity Group name cannot be empty'
        elsif list_affinity_groups.map(&:name).include?(name)
          raise Azure::Error::Error.new(
            'ConflictError',
            409,
            "An affinity group #{name}"\
            " already exists in the current subscription."
          )
        else
          validate_location(location)
          body = Serialization.affinity_group_to_xml(name,
                                                     location,
                                                     label,
                                                     options)
          request_path = '/affinitygroups'
          request = ManagementHttpRequest.new(:post, request_path, body)
          request.call
          Loggerx.info "Affinity Group #{name} is created."
        end
      end

      # Public: updates the label and/or the description for an affinity group
      # for the specified subscription.
      #
      # ==== Attributes
      #
      # * +name+          - String. Affinity Group name.
      # * +label+         - String. Name for the affinity specified as a
      # base-64 encoded string.
      #
      # ==== Options
      #
      # Accepted key/value pairs are:
      # * +:description+   - String. A description for the affinity group.
      # (optional)
      #
      # See http://msdn.microsoft.com/en-us/library/windowsazure/gg715316.aspx
      #
      # Returns:  None
      def update_affinity_group(name, label, options = {})
        raise 'Label name cannot be empty' if label.nil? || label.empty?
        if affinity_group(name)
          body = Serialization.resource_to_xml(label, options)
          request_path = "/affinitygroups/#{name}"
          request = ManagementHttpRequest.new(:put, request_path, body)
          request.call
          Loggerx.info "Affinity Group #{name} is updated."
        end
      end

      # Public: Deletes an affinity group in the specified subscription
      #
      # ==== Attributes
      #
      # * +name+       - String. Affinity Group name.
      #
      # See http://msdn.microsoft.com/en-us/library/windowsazure/gg715314.aspx
      #
      # Returns:  None
      def delete_affinity_group(name)
        if affinity_group(name)
          request_path = "/affinitygroups/#{name}"
          request = ManagementHttpRequest.new(:delete, request_path)
          request.call
          Loggerx.info "Deleted affinity group #{name}."
        end
      end

      # Public: returns the system properties associated with the specified
      # affinity group.
      #
      # ==== Attributes
      #
      # * +name+       - String. Affinity Group name.
      #
      # See http://msdn.microsoft.com/en-us/library/windowsazure/ee460789.aspx
      #
      # Returns:  Azure::BaseManagement::AffinityGroup object
      def get_affinity_group(name)
        if affinity_group(name)
          request_path = "/affinitygroups/#{name}"
          request = ManagementHttpRequest.new(:get, request_path)
          response = request.call
          Serialization.affinity_group_from_xml(response)
        end
      end

      private

      def affinity_group(affinity_group_name)
        if affinity_group_name.nil? ||\
           affinity_group_name.empty? ||\
           !list_affinity_groups.map { |x| x.name.downcase }.include?(
            affinity_group_name.downcase
           )
          error = Azure::Error::Error.new('AffinityGroupNotFound',
                                          404,
                                          'The affinity group does not exist.')
          raise error
        else
          true
        end
      end

      def validate_location(location_name)
        base_mgmt_service = Azure::BaseManagementService.new
        locations = base_mgmt_service.list_locations.map(&:name)
        unless locations.map(&:downcase).include?(location_name.downcase)
          error = "Value '#{location_name}' specified for parameter"\
                  " 'location' is invalid."\
                  " Allowed values are #{locations.join(',')}"
          raise error
        end
      end

      def read_management_certificate(cert)
        cert_file = nil
        begin
          # If it's a String, the type is the extension (.pem, .pfx, .publishsettings)
          if cert.is_a?(String)
            cert = {
              type: File.ext(cert),
              path: cert
            }
          end

          case cert[:type].to_sym
          when :pem
            read_pem(cert)
          when :pfx
            read_pfx(cert)
          when :publishsettings
            read_publishsettings(cert)
          else
            raise ArgumentError, "Unknown type #{type} on Azure.config.management_certificate #{cert}"
          end
        end
      end

      def read_pem(cert)
        cert[:data] ||= cert[:io] ? cert[:io].read : File.open(cert[:path], "r") { |f| f.read }

        certificate_key = OpenSSL::X509::Certificate.new(cert[:data])
        private_key = OpenSSL::PKey::RSA.new(cert[:data])
        [ certificate_key, private_key ]
      end

      def read_pfx(cert)
        cert[:data] ||= cert[:io] ? cert[:io].read : File.open(cert[:path], "rb") { |f| f.read }

        cert_content = OpenSSL::PKCS12.new(Base64.decode64(cert[:data]))
        certificate_key = OpenSSL::X509::Certificate.new(
          cert_content.certificate.to_pem
        )
        private_key = OpenSSL::PKey::RSA.new(cert_content.key.to_pem)
        [ certificate_key, private_key ]
      end

      def read_publishsettings(cert)
        cert[:io] ||= cert[:data] ? StringIO.new(cert[:data]) : File.open(cert[:path], "r")

        # Parse publishsettings content
        publish_settings = Nokogiri::XML(cert[:io])
        subscription_id = Azure.config.subscription_id
        xpath = "//PublishData/PublishProfile/Subscription[@Id='#{subscription_id}']/@ManagementCertificate"
        cert_file = publish_settings.xpath(xpath).text

        read_pfx(data: cert_file, path: cert[:path])
      end
    end
  end
end
