#encoding:utf-8
require 'omniauth-oauth2'
module OmniAuth
  module Strategies
    class Alibaba < OmniAuth::Strategies::OAuth2

      option :client_options, {
        :site           => "https://gw.open.1688.com",
        :authorize_url  => "/auth/authorize.htm",
        #:token_url      => "/openapi/http/1/system.oauth2/getToken/#{options.client_id}"  #不在这里设置，因为这时候client_id还没有初始化
      }

      option :authorize_params, {
        :site =>  'china',
      }

      option :token_params, {
        :grant_type          => 'authorization_code',
        :need_refresh_token => 'true',
        :parse          => :json
      }

      uid { access_token.params['uid'] }

      info do
        {
          :memberId =>access_token.params['memberId'],
          :aliId=>access_token.params['aliId'],
          :resource_owner=>access_token.params['resource_owner'],
          :company_name=>raw_info['companyName'],
          :seller_name=>raw_info['sellerName']
        }
      end

      extra do
        { :raw_info => raw_info }
      end

      def client
        options.client_options[:token_url]="/openapi/http/1/system.oauth2/getToken/#{options.client_id}"
        ::OAuth2::Client.new(options.client_id, options.client_secret, deep_symbolize(options.client_options))
      end
      
      def raw_info
        params={
          :memberId => access_token.params['memberId'],
          :access_token=> access_token.token
        }
        params[:_aop_signature]=Digest::HMAC.hexdigest("param2/1/cn.alibaba.open/member.get/#{client_params[:client_id]}#{params.sort.flatten.join.to_s}", options[:client_secret].to_s, Digest::SHA1).upcase
        @raw_info ||= MultiJson.load(access_token.get("/openapi/param2/1/cn.alibaba.open/member.get/#{client_params[:client_id]}",:params => params).body)['result']['toReturn'].first
      end

      def request_phase
        options.authorize_params[:state] = SecureRandom.hex(24)
        options.authorize_params[:_aop_signature]=Digest::HMAC.hexdigest(client_params.sort.flatten.join.to_s, options[:client_secret].to_s, Digest::SHA1).upcase
        super
      end

      def client_params
        {:client_id => options[:client_id], :redirect_uri => callback_url ,:response_type => "code",:site=>'china',:state=>options.authorize_params[:state]}
      end


      def authorize_params
        params = options.authorize_params.merge(options.authorize_options.inject({}){|h,k| h[k.to_sym] = options[k] if options[k]; h})
        if OmniAuth.config.test_mode
          @env ||= {}
          @env['rack.session'] ||= {}
        end
        session['omniauth.state'] = params[:state]
        params
      end


    end
  end
end