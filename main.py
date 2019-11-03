# Copyright 2013 Google, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#             http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import os
import webapp2
import userCredentialModel
import userModel
import hashlib
from google.appengine.ext.webapp import template 

STATIC_DIR = ""

ADMIN_MOBILE_NUMBER = "9711199289"

def TemplatePath(file_name, directory=STATIC_DIR):
    return os.path.join(os.path.dirname(__file__), directory,file_name)


def AsDictUser(user):
    return {'mobile': user.mobile, 'password': user.password, 'creationTime': user.creationTime, 'lastLogin': user.lastLogin}

def AsDictCredential(credential):
    return {'id': credential.key.id(),
            'mobile': credential.mobile,
            'domain': credential.domain,
            'userName': credential.userName,
            'password': credential.password,
            'comment': credential.comment,
            'timeStamp': credential.timeStamp}

def getAllCredentials(mobile):
    credentials = userCredentialModel.userCredentials(mobile)
    return [AsDictCredential(credential) for credential in credentials]

def getAllUsers():
    users = userModel.AllUsers()
    return [AsDictUser(user) for user in users]

def getAuthCode(id):
    return hashlib.md5(str(id).encode()).hexdigest()


class RestHandler(webapp2.RequestHandler):

    def dispatch(self):
        super(RestHandler, self).dispatch()

    def SendJson(self, r):
        self.response.headers['content-type'] = 'text/plain'
        self.response.write(json.dumps(r))

    def options(self):
        self.response.headers['Access-Control-Allow-Origin']='*'

class MainHandler(RestHandler):
    def get(self):
        obj={}
        obj['user_name']='Aman'
        path=TemplatePath('index.html')
        self.response.out.write(template.render(path, obj))

class PingHandler(RestHandler):
    def get(self):
        self.post()
    def post(self):
        self.response.headers['Access-Control-Allow-Origin'] = '*'
        response = {}
        response["status"] = "success"
        self.SendJson(response)

class LoginHandler(RestHandler):
    def get(self):
        self.post()
    def post(self):
        self.response.headers['Access-Control-Allow-Origin'] = '*'
        response = {}
        response["status"] = "failure"
        r = json.loads(self.request.body)
        user = userModel.getUser(r['mobile'])
        if user is None:
            user = userModel.insertUser(r['mobile'], r['password'], r['timeStamp'], r['timeStamp'])
            response["status"] = "success"
            response["userType"] = "newUser"
            response["authCode"] = getAuthCode(user.key.id()) 
        elif user.password != r['password']:
            response["status"] = "failure"
            response["error"] = "incorrect password"
        else:
            userModel.UpdateUserLoginTime(user.key.id(), r['mobile'], r['password'], r['timeStamp'], r['timeStamp'])
            response["status"] = "success"
            response["authCode"] = getAuthCode(user.key.id()) 
            response["data"] = getAllCredentials(r['mobile'])
            if r['mobile'] == ADMIN_MOBILE_NUMBER:
                response["adminData"] = getAllUsers()
        self.SendJson(response)

class QueryHandler(RestHandler):
    def get(self):
        self.post()
    def post(self):
        self.response.headers['Access-Control-Allow-Origin'] = '*'
        r = json.loads(self.request.body)
        user = userModel.getUser(r['mobile'])
        response = {}
        if user is None:
            response["status"] = "failure"
            response["error"] = "user not found"
        elif r['authCode'] != getAuthCode(user.key.id()):
            response["status"] = "failure"
            response["error"] = "user not authorized"
        else:
            response["status"] = "success"
            response["data"] = getAllCredentials(r['mobile'])
        self.SendJson(response)

class InsertHandler(RestHandler):
    def get(self):
        self.post()
    def post(self):
        self.response.headers['Access-Control-Allow-Origin'] = '*'
        r = json.loads(self.request.body)
        user = userModel.getUser(r['mobile'])
        response = {}
        if user is None:
            response["status"] = "failure"
            response["error"] = "user not found"
        elif r['authCode'] != getAuthCode(user.key.id()):
            response["status"] = "failure"
            response["error"] = "user not authorized"
        else:
            credential = userCredentialModel.insertCredential(r['mobile'], r['domain'], r['userName'], r['password'], r['comment'], r['timeStamp'])
            response["status"] = "success"
            response["create_id"] = credential.key.id()
        self.SendJson(response)

class UpdateHandler(RestHandler):
    def post(self):
        self.response.headers['Access-Control-Allow-Origin']='*' 
        r = json.loads(self.request.body)
        user = userModel.getUser(r['mobile'])
        response = {}
        if user is None:
            response["status"] = "failure"
            response["error"] = "user not found"
        elif r['authCode'] != getAuthCode(user.key.id()) or  r['mobile'] != userCredentialModel.getCredential(r['id']).mobile:
            response["status"] = "failure"
            response["error"] = "user not authorized"
        else:
            credential = userCredentialModel.updateCredential(r['id'], r['mobile'], r['domain'], r['userName'], r['password'], r['comment'], r['timeStamp'])
            response["status"] = "success"
            response["update_id"] = credential.key.id()
        self.SendJson(response)


class DeleteHandler(RestHandler):
    def get(self):
        self.post()
    def post(self):
        self.response.headers['Access-Control-Allow-Origin'] = '*'
        r = json.loads(self.request.body)
        user = userModel.getUser(r['mobile'])
        response = {}
        if user is None:
            response["status"] = "failure"
            response["error"] = "user not found"
        elif r['authCode'] != getAuthCode(user.key.id()) or  r['mobile'] != userCredentialModel.getCredential(r['id']).mobile:
            response["status"] = "failure"
            response["error"] = "user not authorized"
        else:
            userCredentialModel.deleteCredential(r['id'])
            response["status"] = "success"
        self.SendJson(response)

class DeleteUserHandler(RestHandler):
    def get(self):
        self.post()
    def post(self):
        self.response.headers['Access-Control-Allow-Origin'] = '*'
        r = json.loads(self.request.body)
        user = userModel.getUser(r['mobile'])
        response = {}
        if user is None:
            response["status"] = "failure"
            response["error"] = "user not found"
        elif r['authCode'] != getAuthCode(user.key.id()) or (r['mobile'] != ADMIN_MOBILE_NUMBER and r['mobile'] != r['id']):
            response["status"] = "failure"
            response["error"] = "user not authorized"
        else:
            userModel.DeleteUser(userModel.getUser(r['id']).key.id())
            for credential in getAllCredentials(r['id']):
                userCredentialModel.deleteCredential(credential['id'])
            response["status"] = "success"
        self.SendJson(response)


APP = webapp2.WSGIApplication([
    ('/pm/query', QueryHandler),
    ('/pm/insert', InsertHandler),
    ('/pm/delete', DeleteHandler),
    ('/pm/deleteUser', DeleteUserHandler),
    ('/pm/update', UpdateHandler),
    ('/login', LoginHandler),
    ('/ping', PingHandler),
    ('/', MainHandler),
], debug=True)
