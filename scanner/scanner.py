from stem.control import Controller
from stem import Signal
from threading import Timer
from threading import Event

import codecs
import json
import os
import random
import subprocess
import sys
import time

class Scanner:

    def __init__(self, onion_file):
        self.onion_file = onion_file
        self.onions = self.memorize_onions(onion_file)
        self.identity_lock = Event()
        self.identity_lock.set()
        self.session_onions = self.onions
        self.run()

    def memorize_onions(self, onion_file):
        onions = []
        with open(onion_file) as file:
            onions = file.read().splitlines()

        print("[+] Read the file. There were " + str(len(onions)) + " in the file.")
        return onions


    def store_onion(self, onion):
        print("[+] Storing %s in master list." %onion)

        with codecs.open(self.onion_file) as file:
            file.write("%s\n" %onion)

        return

    def handle_timeout(self, process, onion):
        self.identity_lock.clear()

        try:
            process.kill()
            print('[!] Killed the process')
        except Exception as e:
            print('[*] Encountered an error when killing process: ', e)
            pass

        with Controller.from_port(port=9051) as torcontrol:
            torcontrol.authenticate('PythonRocks')
            torcontrol.signal(Signal.NEWNYM)
            time.sleep(torcontrol.get_newnym_wait())
            print('[!] Switched our TOR identity!')

        self.session_onions.append(onion)
        random.shuffle(self.session_onions)

        self.identity_lock.set()

        return


    def scan(self, onion):

        print('[*] Scanning onion: %s' %onion)

        #Firing up process
        process = subprocess.Popen(["onionscan", "-webport 0", "--jsonReport", "--simpleReport=false", onion])

        #start timer to ensure we don't get locked out!
        process_timer = Timer(300, self.handle_timeout, args=[process, onion])
        process_timer.start()

        stdout = process.communicate()[0]

        if process_timer.is_alive():
            process_timer.cancel()
            return stdout

        print("[!] Process timed out")

        return None

    def add_new_onions(self, new_onion_list):

        for linked_onion in new_onion_list:

            if linked_onion not in self.onions and linked_onion.endswith('.onion'):
                print("[+] Discovered new .onion => %s" %linked_onion)

                self.onions.append(linked_onion)
                self.session_onions.append(linked_onion)
                random.shuffle(self.session_onions)
                self.store_onion(linked_onion)

        return

    def process_results(self, onion, json_response):

        if not os.path.exists('onionscan_results'):
            os.mkdir('onionscan_results')

        with open("%s/%s.json" %("onionscan_results", onion), "wb") as file:
            file.write(json_response)

        scan_result = u"%s" %json_response.decode('utf8')
        scan_result = json.loads(scan_result)

        if scan_result['identifierReport']['linkedOnions'] is not None:
            self.add_new_onions(scan_result['identifierReport']['linkedOnions'])

        if scan_result['identifierReport']['relatedOnionDomains'] is not None:
            self.add_new_onions(scan_result['identifierReport']['relatedOnionDomains'])

        if scan_result['identifierReport']['relatedOnionServices'] is not None:
            self.add_new_onions(scan_result['identifierReport']['relatedOnionServices'])

        return

    def run(self):
        count = 0

        while count < len(self.onions):
            self.identity_lock.wait()

            print('[*] Running onion %d of %d' %(count, len(self.onions)))
            onion = self.session_onions.pop()

            if os.path.exists('onionscan_results/%s.json' %onion):

                print('[!] Already retrieved %s. Skipping!' %onion)
                count+=1
                continue

            result = self.scan(onion)

            if result:
                self.process_results(onion, result)
                count+=1