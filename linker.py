#!/usr/bin/env python3

###########################################
#                                         #
#                "Linker"                 #
#       Simple links sharing server,      #
#        to protect links from bot        #
#                                         #
#             Etienne  SELLAN             #
#               13/10/2019                #
#                                         #
###########################################

import sys
import time
import signal
import threading
from threading import Thread
from http.server import HTTPServer, BaseHTTPRequestHandler
import cgi
from socketserver import ThreadingMixIn
import os
import binascii
import shutil
import base64
import math
import hashlib
import pyAesCrypt
import requests
import json

# SETTINGS BEGIN
settings = {}
settings["url"] = "https://linker.sellan.fr"
settings["listen_address"] = "0.0.0.0"
settings["port"] = 80
settings["directory"] = "/tmp"
settings["delete_limit"] = (30 * 24)  # hours
settings["cleaning_interval"] = 1  # hours
settings["id_length"] = 4  # bytes
settings["max_link_length"] = 1024  # chars
settings["enable_logs"] = False
settings["logs_path"] = "/var/log"
settings["recaptcha_public_key"] = ''
settings["recaptcha_private_key"] = ''
settings["recaptcha_api_url"] = "https://www.google.com/recaptcha/api/siteverify"
# SETTINGS END

def settings_initialisation():
    for setting in settings:
        # Take environment settings if defined
        if ("linker_"+setting) in os.environ:
            settings[setting] = os.environ[("linker_"+setting)]
    settings["current_directory"] = os.path.dirname(os.path.realpath(__file__))

def path_to_array(path):
    # Split path
    path_array = path.split('/')
    # Remove empty elements
    path_array = [element for element in path_array if element]
    return path_array


def array_to_path(path_array):
    # Join array
    path = '/' + '/'.join(path_array)
    return path


def write_logs(message,error=False):
    print(message)
    if settings["enable_logs"]:
        now = time.asctime(time.localtime(time.time()))
        logs_file = 'request.log' if error else 'error.log'
        logs_full_path = array_to_path(settings["logs_path"] + [logs_file])
        with open(logs_full_path, 'a') as logs:
            logs.write("{} : {}\n".format(now, message))

def path_initialisation():
    global directory
    directory = path_to_array(settings["directory"])
    directory.append("linker")
    # Create directory for Linker if not exist
    if not os.path.exists(array_to_path(directory)):
        os.makedirs(array_to_path(directory), 666)
    global logs_path
    logs_path = path_to_array(settings["logs_path"])
    logs_path.append("linker")
    # Create directory for Linker if not exist
    if not os.path.exists(array_to_path(logs_path)):
        os.makedirs(array_to_path(logs_path), 666)


def initialisation():
    settings_initialisation()
    path_initialisation()

class request_handler(BaseHTTPRequestHandler):
    def do_GET(self):  # For home page and link access
        if len(self.path) > 1:
            with open(settings["current_directory"]+'/'+'check.html', 'r') as checkpage:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                # Send HTML page with replaced data
                html = checkpage.read()
                html = html.replace("[url]", settings["url"])
                html = html.replace("[recaptcha_public_key]", settings["recaptcha_public_key"])
                self.wfile.write(str.encode(html))
        else:
            # Open HTML homepage file
            with open(settings["current_directory"]+'/'+'index.html', 'r') as homepage:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                # Send HTML page with replaced data
                html = homepage.read()
                html = html.replace("[url]", settings["url"])
                html = html.replace("[delete_limit]", human_readable_time(int(settings["delete_limit"]) * 60 * 60))
                self.wfile.write(str.encode(html))
        return

    def do_POST(self):
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD': 'POST'}
        )

        if form.getvalue("link"):
            link = form.getvalue("link")

            self.send_response(200)  # Send success header
            self.send_header('Content-type', 'application/json')  # Send mime
            self.end_headers()  # Close header
            
            if len(link) > int(settings["max_link_length"]):  # Check link length
                HTML_error = "Error: Link too long (max {} chars)\n"
                HTML_error = HTML_error.format(settings["max_link_length"])
                self.wfile.write(str.encode(HTML_error))  # Return error
                return
            
            # Loop for generating uniq token
            while "Bad token":
                # Get random token from urandom
                random_token = binascii.hexlify(os.urandom(int(settings["id_length"]))).decode()
                # If directory not exist -> token free
                link_key = hashlib.sha512(('/'+random_token).encode('utf-8')).hexdigest()
                link_key_digest = hashlib.sha512(link_key.encode('utf-8')).hexdigest()
                if not os.path.isfile(array_to_path(directory+[link_key_digest])):
                    break
            
            # Concat the new file full path
            self.file_path = directory+[link_key_digest]
            # Open tmp new file to write binary data
            current_file = open(array_to_path(self.file_path)+".clear", "w")

            # Write content of request
            current_file.write(link)
            current_file.close()

            pyAesCrypt.encryptFile(array_to_path(self.file_path)+".clear", array_to_path(self.file_path), link_key, (64*1024))
            os.remove(array_to_path(self.file_path)+".clear")
            # Return new file url to user
            response = {}
            response["state"] = "OK"
            response["link"] = settings["url"]+"/"+random_token
            self.wfile.write(str.encode(json.dumps(response)))
            return

        elif form.getvalue("token"):

            data = {'secret':settings["recaptcha_private_key"], 
                    'response':form.getvalue("token").replace('"', '')}

            r = requests.post(url = settings["recaptcha_api_url"], data = data)
            result = json.loads(r.text)

            if result["success"]:
                self.request_path = self.path
                link_key = hashlib.sha512(self.request_path.encode('utf-8')).hexdigest()
                link_key_digest = hashlib.sha512(link_key.encode('utf-8')).hexdigest()
                # Convert path of request to array for easy manipulation
                self.request_path = path_to_array(self.request_path)
                # Construct full path of the file
                self.file_path = directory + [link_key_digest]

                if len(self.request_path) > 0:
                    print(array_to_path(self.file_path))
                    if os.path.exists(array_to_path(self.file_path)):
                        with open(array_to_path(self.file_path), 'rb') as self.file:
                            # Load file stats
                            self.file.stat = os.fstat(self.file.fileno())

                            decrypted_file_path = array_to_path(self.file_path)+'.clear'
                            print(decrypted_file_path)
                            pyAesCrypt.decryptFile(array_to_path(self.file_path), decrypted_file_path, link_key, (64*1024))
                            self.file = open(decrypted_file_path, 'r')
                            #self.file.stat = os.fstat(self.file.fileno())

                            self.send_response(200)
                            self.send_header("Content-Type", 'text/plain')
                            self.end_headers()

                            response = {}
                            response["state"] = "OK"
                            response["link"] = self.file.read().replace('"','')

                            os.remove(decrypted_file_path)

                            self.wfile.write(str.encode(json.dumps(response)))
                    else:
                        self.send_response(404)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        self.response = "Link not found \n"
                        self.wfile.write(str.encode(self.response))
            else:
                self.send_response(403)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.response = "Verification failed\n"
                self.wfile.write(str.encode(self.response))


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass

def run_on(port):
    print("\n")
    print("/---------------------------------\\")
    print("|  Starting Linker on port {}  |".format(str(settings["port"]).rjust(5, " ")))
    print("\\---------------------------------/")
    print("\n")
    print("\n\nLogs : \n")
    server_address = (settings["listen_address"], int(settings["port"]))
    httpd = ThreadedHTTPServer(server_address, request_handler)
    httpd.serve_forever()


def human_readable_time(seconds):  # Convert time in seconds to human readable string format
    units = ['second', 'minute', 'hour', 'day', 'week', 'month', 'year']
    maximum_values = [60, 60, 24, 7, 4, 12, 99]
    cursor = 0
    while seconds > maximum_values[cursor]:
        seconds /= maximum_values[cursor]
        cursor += 1
    value = math.ceil(seconds)
    unit = units[cursor]
    if float(value) > 1:
        unit += 's'
    return str(value)+' '+unit


def set_interval(func, time):
    e = threading.Event()
    while not e.wait(time):
        func()


def clean_files():
    # Create list of deleted files
    removed = []
    now = time.time()
    # Compute the limit_date from setings
    limit_date = now - (int(settings["delete_limit"]) * 3600)
    
    for file in os.listdir(array_to_path(directory)):
        if os.path.isfile(array_to_path(directory+[file])):
            # Get informations about this file
            stats = os.stat(array_to_path(directory+[file]))
            timestamp = stats.st_mtime
            if timestamp < limit_date:
                removed.append(file)
                os.remove(array_to_path(directory+[file]))

    if len(removed) > 0:
        write_logs("Files removed : {}".format(', '.join(removed)))


if __name__ == "__main__":
    server = Thread(target=run_on, args=[int(settings["port"])])
    server.daemon = True
    server.start()
    initialisation()
    # Launch auto cleaning interval
    set_interval(clean_files, (int(settings["cleaning_interval"]) * 3600))
    signal.pause()
