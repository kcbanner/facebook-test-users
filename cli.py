#!/usr/bin/env python2

import sys
import urllib
import urllib2
import httplib
import simplejson
from pprint import pprint
from optparse import OptionParser

GRAPH_URL = 'graph.facebook.com' 

def get_access_token(app_id, app_secret):
    f = urllib2.urlopen("https://%s/oauth/access_token?client_id=%s&client_secret=%s&grant_type=client_credentials" %
                        (GRAPH_URL, app_id, app_secret))
    return f.read()

def load_users(app_id, access_token):
    f = urllib2.urlopen("https://%s/%s/accounts/test-users?%s" % (GRAPH_URL, app_id, access_token))
    return simplejson.loads(f.read())['data']

def create_user(app_id, access_token, installed=None, permissions=None):
    data = {}
    if installed is not None:
        data['installed'] = installed
    if permissions is not None and len(permissions) > 0:
        data['permissions'] = permissions

    f = urllib2.urlopen("https://%s/%s/accounts/test-users?%s" % (GRAPH_URL, app_id, access_token),
                        data=urllib.urlencode(data))
    return simplejson.loads(f.read())

def delete_user(user_id, access_token):
    conn = httplib.HTTPSConnection(GRAPH_URL)
    conn.request('DELETE', "/%s?%s" % (user_id, access_token))
    r = conn.getresponse()
    content = r.read()
    
    if content == 'true':
        return True
    else:
        return False

def print_users(users):
    print 'Users: '
    i = 1
    for user in users:
        print "  %s - %s:\n        login_url: %s\n        token: %s" % (i, user['id'], user['login_url'], user['access_token'])
        i += 1

def find_user(user_id, users):
    u = None
    for user in users:
        if user['id'] == user_id:
            u = user
            break
    return u

def question(question, options):
    while True:
        options_str = '/'.join(options)
        answer = raw_input(" %s (%s): " % (question, options_str)).strip().upper()        
        if answer in options:
            return answer

if __name__ == '__main__':
    usage = "usage: %prog <app_id> <app_secret>"
    parser = OptionParser(usage=usage)
    (options, args) = parser.parse_args()

    if len(args) != 2:
        parser.error('App ID and secret are required')
        sys.exit(1)

    app_id = args[0]
    app_secret = args[1]

    print 'Getting access token...',
    access_token = get_access_token(app_id, app_secret)
    print 'done.'

    print 'Getting user list...',
    users = load_users(app_id, access_token)
    print 'done.'

    print_users(users)


    while True:
        try:
            input = raw_input('Command (? for help): ')
            if len(input) != 0:
                cmd = input.strip()
                if cmd == '?':
                    print "Command action\n  a  Add user\n  l  List users\n  d  Delete user\n  f  Friend users\n"
                elif cmd == 'a':
                    installed = question('Installed', ['Y', 'N'])
                    installed_options = {'Y': 'true', 'N': 'false'}
                    permissions = raw_input(' Permissions (comma seperated): ')
                    new_user = create_user(app_id,
                                           access_token,
                                           installed_options[installed],
                                           permissions)
                    users.append(new_user)
                    print_users(users)
                elif cmd == 'l':
                    users = load_users(app_id, access_token)
                    print_users(users)
                elif cmd == 'd':
                    try:
                        user_num = int(raw_input(' User #: '))-1
                        user = users[user_num]
                        r = delete_user(user['id'], access_token)
                        if r:
                            print 'User deleted.'
                        else:
                            print 'User not deleted.'
                    except (IndexError, ValueError), e:
                        print e
                        print 'Invalid user number.'
        except EOFError, e:
            sys.exit(1)
