#!/usr/bin/env python
# encoding: utf-8
"""
main.py

Created by Darcy Liu on 2014-05-28.
Copyright (c) 2014 Darcy Liu. All rights reserved.
"""
import os
import socket
import uuid
import plistlib

import tornado.web
from tornado.options import define, options

def general_payload():
    payload = {
        'PayloadVersion': 1,
        'PayloadUUID': str(uuid.uuid1()),
        'PayloadOrganization': 'Over-the-Air Profile Service'
    }
    return payload
    
def profile_service_payload(service_address, challenge):
    payload = general_payload()

    payload['PayloadType'] = "Profile Service" # do not modify
    payload['PayloadIdentifier'] = "com.example.mobileconfig.profile-service"

    # strings that show up in UI, customisable
    payload['PayloadDisplayName'] = "Over-the-Air Profile Service"
    payload['PayloadDescription'] = "Install this profile to enroll for secure access to Example Inc."

    payload_content = {}
    payload_content['URL'] = '%s/profile' % (service_address)
    payload_content['DeviceAttributes'] = [
            'UDID', 
            'VERSION',
            'PRODUCT',              # ie. iPhone1,1 or iPod2,1
            'MAC_ADDRESS_EN0',      # WiFi MAC address
            'DEVICE_NAME',          # given device name "iPhone"

            # Items below are only available on iPhones
            'IMEI',
            'ICCID'
        ];
    if challenge and len(challenge)>0:
        payload_content['Challenge'] = challenge

    payload['PayloadContent'] = payload_content
    return payload

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        udid = self.get_argument('udid',None)
        self.render('index.html',udid=udid)
        
class CAHandler(tornado.web.RequestHandler):
    def get(self):
        with open('ca_cert.pem', 'rb') as f:  
            self.set_header('Content-Type', 'application/x-x509-ca-cert')                
            self.write(f.read())
            
class EnrollHandler(tornado.web.RequestHandler):
    def get(self):
        service_address = '%s://%s' % (self.request.protocol,self.request.host)
        configuration = profile_service_payload(service_address, 'signed-auth-token')
        #signed_profile = sign_data('ssl_private.pem',b64encode(plistlib.writePlistToString(configuration)))
        signed_profile = plistlib.writePlistToString(configuration)
        self.set_header('Content-Type', 'application/x-apple-aspen-config')
        self.set_header('Content-Disposition', 'attachment; filename=enroll.mobileconfig')
        self.write(signed_profile)

class ProfileHandler(tornado.web.RequestHandler):
    def get(self):
        pass
    def post(self):
        signed_profile = self.request.body
        begin = '<?xml version="1.0"'
        end = '</plist>'
        b = signed_profile.find(begin)
        e = signed_profile.find(end) + len(end)
        configuration = signed_profile[b:e]
        plist = plistlib.readPlistFromString(configuration)

        challenge = plist['CHALLENGE']
        
        udid = plist['UDID']
        product = plist['PRODUCT']
        version = plist['VERSION']
        
        # Items below are only available on iPhones
        imei = ''
        if plist.has_key('IMEI'):
            imei = plist['IMEI']
        iccid = ''
        if plist.has_key('ICCID'):
            iccid = plist['ICCID']
            
        params = '?challenge=%s&udid=%s&product=%s&version=%s&imei=%s&iccid=%s'%(challenge,udid,product,version,imei,iccid)
        self.redirect('/'+params,permanent=True)

class SCEPHandler(tornado.web.RequestHandler):
    def get(self):
        print 'Query #', self.request.query
        
        operation = self.get_argument('operation',None)
        if operation == 'GetCACert':
            print 'GetCACert'
            self.set_header('Content-Type', 'application/x-x509-ca-ra-cert')
            self.write('GetCACert')
        elif operation == 'GetCACaps':
            print 'GetCACaps'
            self.set_header('Content-Type', 'text/plain')
            self.write('POSTPKIOperation\nSHA-1\nDES3\n')
        elif operation == 'PKIOperation':
            print 'PKIOperation'
            self.set_header('Content-Type', 'application/x-pki-message')
            self.write('PKIOperation')
        else:
            self.write('''operations:
                        <a href="/scep?operation=GetCACert">GetCACert</a> | 
                        <a href="/scep?operation=GetCACaps">GetCACaps</a>   |
                        <a href="/scep?operation=PKIOperation">PKIOperation</a>  ''')

settings = {
    'debug': True,
    'static_path': os.path.join(os.path.dirname(__file__), 'static'),
    'template_path': os.path.join(os.path.dirname(__file__), '_templates'),
    'cookie_secret': 'random string',
    'xsrf_cookies': False,
    'autoescape': None,
}

handlers = [
    (r'/', MainHandler),
    (r'/CA', CAHandler),
    (r'/enroll',EnrollHandler),
    (r'/profile',ProfileHandler),
    (r'/scep',SCEPHandler),
]

application = tornado.web.Application(handlers,**settings)

ssl_options = {
    'certfile': os.path.join('ssl_cert.pem'),
    'keyfile': os.path.join('ssl_private.pem'),
}

define('port', default=8443, help='run on the given port', type=int)

if __name__ == '__main__':
    import tornado.ioloop
    import tornado.httpserver
    
    tornado.options.parse_command_line()
    #http_server = tornado.httpserver.HTTPServer(application, ssl_options=ssl_options)
    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(options.port)
    print 'server address: https://%s:%i' %(socket.gethostbyname(socket.gethostname()),options.port)
    tornado.ioloop.IOLoop.instance().start()