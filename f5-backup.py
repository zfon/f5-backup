#! /usr/bin/env python
# -*- coding: utf-8 -*-
# https://github.com/sebastien6/f5-backup

import os
import json
import datetime
import requests
import getpass
import optparse
import sys
import hashlib
from urllib3.exceptions import InsecureRequestWarning
import yaml
import os.path
import pprint
import logging

# Root CA for SSL verification
ROOTCA = ''
CHECKSUM = ''
HOSTNAME = ''

CONFIG_FILE = 'f5-backup.yml'

def load_config(config_file):
    with open(config_file, 'r') as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            logging.error(exc)

def pp(*stuff):
    pp = pprint.PrettyPrinter(indent=4)
    return pp.pprint(stuff)
    
# credential Ask for user Active Directory authentication information
# with a verification of entered password
def credential():
    #User name capture
    user = raw_input('Enter Active Directory Username: ')
    # start infinite loop
    while True:
        # Capture password without echoing 
        pwd1 = getpass.getpass('%s, enter your password: ' % user)
        pwd2 = getpass.getpass('%s, re-Enter Password: ' % user)
        # Compare the two entered password to avoid typo error
        if pwd1 == pwd2:
            # break infinite loop by returning value
            return user, pwd1

# get_token() will call F5 Big-ip API with username and password to obtain an authentication
# security token
def get_token(session, username, password):
    # Build URL
    URL_AUTH = 'https://%s/mgmt/shared/authn/login' % HOSTNAME
    
    # prepare payload for request
    payload = {}
    payload['username'] = username
    payload['password'] = password
    payload['loginProviderName'] = 'tmos'

    # set authentication to username and password to obtain the security authentication token
    session.auth = (username, password)

    # send request and handle connectivity error with try/except
    try:
        resp = session.post(URL_AUTH, json.dumps(payload)).json()
    except Exception as e:
        logging.error("Error sending request to F5 big-ip. Check your hostname or network connection")
        raise e
    
    # filter key in response. if 'code' key present, answer was not a 200 and error message with code is printed.
    for k in resp.keys():
        if k == 'code':
            logging.error('security authentication token creation failure. Error: %s, Message: %s' % (resp['code'],resp['message']))
            raise
    
    # Print a successful message log and return the generated token
    logging.info('Security authentication token for user %s was successfully created' % resp['token']['userName'])
    return resp['token']['token']

# create_ucs will call F5 Big-ip API with security token authentication to create a timestamps ucs backup
# file of the F5 Big-ip device configuration
def create_ucs(session):
    URL_UCS = 'https://%s/mgmt/tm/sys/ucs' % HOSTNAME

    # generate a timestamp file name
    ucs_filename = HOSTNAME + '_' + datetime.datetime.now().strftime('%Y-%m-%d-%H%M%S') + '.ucs'

    # prepare the http request payload
    payload = {}
    payload['command'] = 'save'
    payload['name'] = ucs_filename

    # send request and handle connectivity error with try/except
    try:
        resp = session.post(URL_UCS, json.dumps(payload)).json()
    except Exception as e:
        logging.error("Error sending request to F5 big-ip. Check your hostname or network connection")
        raise e
    
    # filter key in response. if 'code' key present, answer was not a 200 and error message with code is printed.
    for k in resp.keys():
        if k == 'code':
            logging.error('UCS backup creation failure. Error: %s, Message: %s' % (resp['code'],resp['message']))
            raise

    # Print a successful message log
    logging.info("UCS backup of file %s on host %s successfully completed" % (resp['name'], HOSTNAME))

    return ucs_filename, checksum(session, ucs_filename)

def checksum(session, filename):
    URL_BASH = 'https://%s/mgmt/tm/util/bash' % HOSTNAME

    # prepare the http request payload
    payload = {}
    payload['command'] = 'run'
    payload['utilCmdArgs'] = '''-c "sha256sum /var/local/ucs/%s"''' % filename
    # send request and handle connectivity error with try/except
    try:
        resp = session.post(URL_BASH, json.dumps(payload)).json()['commandResult']
    except Exception as e:
        logging.error("Error sending request to F5 big-ip. Check your hostname or network connection")
        raise e

    checksum = resp.split()
    logging.info('Remote checksum: ' + str(checksum[0]))
    return checksum[0]

# delete_ucs will call F5 Big-ip API with security token authentication to delete the ucs backup
# file after local download
def delete_ucs(session, ucs_filename):
    URL_BASH = 'https://%s/mgmt/tm/util/bash' % HOSTNAME
    # prepare the http request payload
    payload = {}
    payload['command'] = 'run'
    payload['utilCmdArgs'] = '''-c "rm -f /var/local/ucs/%s"''' % ucs_filename
    # send request and handle connectivity error with try/except
    try:
        session.post(URL_BASH, json.dumps(payload)).json()
    except Exception as e:
        logging.error("Error sending request to F5 big-ip. Check your hostname or network connection")
        raise e

def ucsDownload(ucs_filename, token, path):
    global STATUS

    # Build request URL
    URL_DOWNLOAD = 'https://%s/mgmt/shared/file-transfer/ucs-downloads/' % HOSTNAME

    # Define chunck size for UCS backup file
    chunk_size = 512 * 1024

    # Define specific request headers
    headers = {
        'Content-Type': 'application/octet-stream',
        'X-F5-Auth-Token': token
    }
    
    # set filename and uri for request
    filename = os.path.basename(ucs_filename)
    uri = '%s%s' % (URL_DOWNLOAD, filename)
    
    requests.packages
    with open(path + ucs_filename, 'wb') as f:
        start = 0
        end = chunk_size - 1
        size = 0
        current_bytes = 0

        while True:
            content_range = "%s-%s/%s" % (start, end, size)
            headers['Content-Range'] = content_range

            #print headers
            resp = requests.get(uri,
                                headers=headers,
                                verify=False,
                                stream=True)

            if resp.status_code == 200:
                # If the size is zero, then this is the first time through the
                # loop and we don't want to write data because we haven't yet
                # figured out the total size of the file.
                if size > 0:
                    current_bytes += chunk_size
                    for chunk in resp.iter_content(chunk_size):
                        f.write(chunk)

                # Once we've downloaded the entire file, we can break out of
                # the loop
                if end == size:
                    break

            crange = resp.headers['Content-Range']

            # Determine the total number of bytes to read
            if size == 0:
                size = int(crange.split('/')[-1]) - 1

                # If the file is smaller than the chunk size, BIG-IP will
                # return an HTTP 400. So adjust the chunk_size down to the
                # total file size...
                if chunk_size > size:
                    end = size

                # ...and pass on the rest of the code
                continue

            start += chunk_size

            if (current_bytes + chunk_size) > size:
                end = size
            else:
                end = start + chunk_size - 1
    f.close()
    if sha256_checksum(path + ucs_filename) == CHECKSUM:
        STATUS = True

def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    f.close()
    logging.info('Local checksum:  ' + str(sha256.hexdigest()))
    return sha256.hexdigest()

def f5Backup(hostname, username, password, path):
    global STATUS,CHECKSUM,HOSTNAME
    counter = 0
    HOSTNAME = hostname
    STATUS = False
    
    # Disable SSL warning for Insecure request
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    
    # create a new https session
    session = requests.Session()

    # update session header
    session.headers.update({'Content-Type': 'application/json'})
    
    # Disable TLS cert verification
    if ROOTCA == '':
        session.verify = False
    else:
        session.verify = ROOTCA

    # set default request timeout
    session.timeout = '30'

    # get a new authentication security token from F5
    logging.info('>>>> Start remote backup F5 big-Ip device %s ' % HOSTNAME)
    token = get_token(session, username, password)
    
    # disable username, password authentication and replace by security token 
    # authentication in the session header
    session.auth = None
    session.headers.update({'X-F5-Auth-Token': token})
    
    # create a new F5 big-ip backup file on the F5 device
    logging.info('Creation UCS backup file on F5 device %s' % HOSTNAME)
    ucs_filename, CHECKSUM = create_ucs(session)
    
    # locally download the created ucs backup file
    #download_ucs(session, ucs_filename)
    while not STATUS:
        logging.info("Download file %s attempt %s" % (ucs_filename, counter+1))
        ucsDownload(ucs_filename, token, path)
        counter+=1
        if counter >2:
            logging.error('UCS backup download failure. inconscistent' \
            'checksum between origin and destination')
            logging.error('program will exit and ucs file will not be deleted from F5 device')
            raise
    
    logging.info('UCS backup checksum verification successful')

    # delete the ucs file from f5 after local download
    # to keep f5 disk space clean
    delete_ucs(session, ucs_filename)

if __name__ == "__main__":
	
    # Define a new argument parser
    parser=optparse.OptionParser()

    # import options
    parser.add_option('--hostname', help='Pass the F5 Big-ip hostname')

    # Parse arguments
    (opts,args) = parser.parse_args()
    
    # Check if --hostname argument populated or not
    if not opts.hostname:
        if os.path.exists(CONFIG_FILE):
            config = load_config(CONFIG_FILE)
            
            #logging init
            logger = logging.getLogger('')
            logger.setLevel(eval(config['logging']['level']))
            
            if not os.path.exists(config['backups']['path']):
                logging.error('>> Backup path "%s" does not exist.' % config['backups']['path'])
                exit(1)
            if not os.path.exists(config['logging']['path']):
                logging.error('>> Logging path "%s" does not exist.' % config['backups']['path'])
                exit(1)      
                      
            if config['logging']['print']:
                ch_stdout_logformat = logging.Formatter(config['logging']['logStdOutformat'])
                ch_stdout = logging.StreamHandler(sys.stdout)
                ch_stdout.setFormatter(ch_stdout_logformat)
                logger.addHandler(ch_stdout)
            
            ch_file_logformat = logging.Formatter(config['logging']['logFileformat'])
            ch_file = logging.FileHandler("{0}/{1}".format(config['logging']['path'], config['logging']['filename']))
            ch_file.setFormatter(ch_file_logformat)
            logger.addHandler(ch_file)
            
            # Backup begins
            logging.info('#### Starting backup operation for %s ####' % config['devices'])
            for device in config['devices']:
                path = config['backups']['path']
                if config['backups']['use_hostname']:
                    path += device + '/'
                    if not os.path.exists(path):
                        logging.info('Directory "%s" does not exist, creating it...' % path)
                        os.makedirs(path)
                try:
                    f5Backup(device, config['credentials']['username'], config['credentials']['password'], path)
                    logging.info('<<<< backup of %s successfully finish.' % device)
                except Exception as e:
                    logging.error('<<<< backup of %s failed.' % device, exc_info=True)
                    continue
            logging.info('#### Finish backup operation for %s ####' % config['devices'])
            exit()
        else:
            logging.error('--hostname argument is required.')
            exit(1)
    else:
        #logging init
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s-%(process)d-%(levelname)s-%(message)s')
        # Request user credential
        username, password = credential()
        try:
            f5Backup(opts.hostname, username, password, './')
        except:
           logging.error('<<<< backup of %s failed.' % opts.hostname, exc_info=True) 
           exit(1)
