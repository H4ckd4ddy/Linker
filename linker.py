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

import time
import signal
import threading
from threading import Thread
from http.server import HTTPServer, BaseHTTPRequestHandler
import cgi
from socketserver import ThreadingMixIn
import os
import math
import hashlib
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
settings["max_link_length"] = 32768  # chars
settings["enable_logs"] = False
settings["logs_path"] = "/var/log"
settings["recaptcha_public_key"] = ''
settings["recaptcha_private_key"] = ''
settings["recaptcha_api_url"] = "https://www.google.com/recaptcha/api/siteverify"
# SETTINGS END

static_files = ['Github-ribbon.png', 'script.js', 'style.css']

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
        self.request_path = path_to_array(self.path)
        if len(self.request_path) > 0:
            if self.request_path[0] in static_files:
                static_file_index = static_files.index(self.request_path[0])
                static_file_name = static_files[static_file_index]
                with open(settings["current_directory"]+'/'+static_file_name, 'rb') as static_file:
                    self.send_response(200)
                    #self.send_header('Content-type', 'image/png')
                    self.end_headers()
                    self.wfile.write(static_file.read())
                return
        # Open HTML homepage file
        with open(settings["current_directory"]+'/'+'index.html', 'r') as homepage:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            # Send HTML page with replaced data
            html = homepage.read()
            html = html.replace("[url]", settings["url"])
            html = html.replace("[recaptcha_public_key]", settings["recaptcha_public_key"])
            html = html.replace("[delete_limit]", human_readable_time(int(settings["delete_limit"]) * 60 * 60))
            self.wfile.write(str.encode(html))
        return

    def do_POST(self):
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD': 'POST'}
        )

        if form.getvalue("link_id") and form.getvalue("encrypted_link"):
            link_id = form.getvalue("link_id")
            encrypted_link = form.getvalue("encrypted_link")
            
            if len(encrypted_link) > int(settings["max_link_length"]):  # Check link length
                self.send_response(413)  # Send error header
                self.end_headers()  # Close header
                HTML_error = "Error: Link too long (max {} chars)\n"
                HTML_error = HTML_error.format(settings["max_link_length"])
                self.wfile.write(str.encode(HTML_error))  # Return error
                return

            # Hash link_id
            file_name = hashlib.sha512(link_id.encode('utf-8')).hexdigest()
            
            # Concat the new file full path
            self.file_path = directory+[file_name]
            
            # Check if file already exist
            if os.path.exists(array_to_path(self.file_path)):
                self.send_response(409)  # Send error header
                self.end_headers()  # Close header
                HTML_error = "Error: Another link exists with the same id\n"
                self.wfile.write(str.encode(HTML_error))  # Return error
                return
            
            # Open tmp new file to write binary data
            current_file = open(array_to_path(self.file_path), "w")

            # Write content of request
            current_file.write(encrypted_link)
            current_file.close()
            
            self.send_response(200)  # Send success header
            self.send_header('Content-type', 'application/json')  # Send mime
            self.end_headers()  # Close header

            # Return new file url to user
            response = {}
            response["state"] = "OK"
            response["msg"] = "Link protected !"
            self.wfile.write(str.encode(json.dumps(response)))
            return

        elif form.getvalue("link_id") and form.getvalue("token") :

            data = {'secret':settings["recaptcha_private_key"], 
                    'response':form.getvalue("token").replace('"', '')}

            r = requests.post(url = settings["recaptcha_api_url"], data = data)
            result = json.loads(r.text)

            if result["success"]:
                self.request_path = self.path
                link_id = form.getvalue("link_id")
                file_name = hashlib.sha512(link_id.encode('utf-8')).hexdigest()
                
                # Construct full path of the file
                self.file_path = directory + [file_name]
                
                if os.path.exists(array_to_path(self.file_path)):
                    with open(array_to_path(self.file_path), 'r') as self.file:
                        # Load file stats
                        self.file.stat = os.fstat(self.file.fileno())

                        self.send_response(200)
                        self.send_header("Content-Type", 'application/json')
                        self.end_headers()

                        response = {}
                        response["state"] = "OK"
                        response["encrypted_link"] = self.file.read()

                        self.wfile.write(str.encode(json.dumps(response)))
                else:
                    self.send_response(404)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.response = "Link not found \n"
                    self.wfile.write(str.encode(self.response))
            else:
                self.send_response(403)
                self.send_header('Content-type', 'text/plain')
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
