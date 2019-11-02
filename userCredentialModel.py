# Copyright 2013 Google, Inc
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

from google.appengine.ext import ndb

class Credential(ndb.Model):
    mobile = ndb.StringProperty()
    domain = ndb.StringProperty()
    userName = ndb.StringProperty()
    password = ndb.StringProperty()
    comment = ndb.StringProperty()
    timeStamp = ndb.StringProperty()

def AllCredential():
    return Credential.query()

def userCredentials(mobile):
    return Credential.query().filter(ndb.GenericProperty("mobile") == mobile)

def getCredential(id):
    return ndb.Key(Credential, id).get()

def updateCredential(id, mobile, domain, userName, password, comment, timeStamp):
    credential = Credential(id=id, mobile=mobile, domain=domain, userName=userName, password=password, comment=comment, timeStamp=timeStamp)
    credential.put()
    return credential

def insertCredential(mobile, domain, userName, password, comment, timeStamp):
    credential = Credential(mobile=mobile, domain=domain, userName=userName, password=password, comment=comment, timeStamp=timeStamp)
    credential.put()
    return credential

def deleteCredential(id):
    credential = ndb.Key(Credential, id)
    credential.delete()