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


class User(ndb.Model):
    mobile = ndb.StringProperty()
    password = ndb.StringProperty()
    creationTime = ndb.StringProperty()
    lastLogin = ndb.StringProperty()


def AllUsers():
    return User.query()

def getUser(mobile):
    return User.query().filter(ndb.GenericProperty("mobile") == mobile).get()


def UpdateUserLoginTime(id, mobile, password, creationTime, lastLogin):
    user = User(id=id, mobile=mobile, password=password, creationTime=creationTime, lastLogin=lastLogin)
    user.put()
    return user


def insertUser(mobile, password, creationTime, lastLogin):
    user = User(mobile=mobile, password=password, creationTime=creationTime, lastLogin=lastLogin)
    user.put()
    return user


def DeleteUser(id):
    key = ndb.Key(User, id)
    key.delete()
