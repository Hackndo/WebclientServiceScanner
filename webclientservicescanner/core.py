#!/usr/bin/env python
# Description:
#   Multithreaded tool to scan for Webclient service "DAV RPC SERVICE" named pipe
#
# Author:
#   pixis (@hackanddo)
#
# Acknowledgments:
#   @tifkin_ https://twitter.com/tifkin_/status/1419806476353298442


from __future__ import division
from __future__ import print_function

import signal
import threading
from queue import Queue

from impacket.smbconnection import SMBConnection

lock = threading.RLock()


class COLORS:
    GREEN = '\033[92m'
    RED = '\033[91m'
    ENDC = '\033[0m'


class Worker(threading.Thread):
    def __init__(self, task_q):
        super().__init__()
        self.task_q = task_q
        self.shutdown_flag = threading.Event()

    def run(self):
        while not self.shutdown_flag.is_set():
            worker_scanner = self.task_q.get()
            self.name = worker_scanner.address
            worker_scanner.run()
            self.task_q.task_done()


class ThreadPool:
    def __init__(self, targets, smb_version, username, password, domain, lmhash, nthash, aesKey, dc_ip, k, threads, debug):
        self.targets = targets
        self.smb_version = smb_version
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.aesKey = aesKey
        self.dc_ip = dc_ip
        self.k = k
        self.threads = []
        self.max_threads = threads
        self.debug = debug
        self.task_q = Queue(self.max_threads+10)
        signal.signal(signal.SIGINT, self.interrupt_event)
        signal.signal(signal.SIGTERM, self.interrupt_event)

    def interrupt_event(self, signum, stack):
        print("**CTRL+C** QUITTING GRACEFULLY")
        self.stop()
        raise KeyboardInterrupt

    def stop(self):
        for thread in self.threads:
            thread.shutdown_flag.set()
        for thread in self.threads:
            thread.join()

    def isRunning(self):
        return any(thread.is_alive() for thread in self.threads)

    def run(self):
        threading.current_thread().name = "[Main Thread]"

        try:
            # Turn-on the worker threads
            for i in range(self.max_threads):
                thread = Worker(self.task_q)
                thread.daemon = True
                self.threads.append(thread)
                thread.start()

            instance_id = 1
            for target in self.targets:
                self.task_q.put(WebdavClientScanner(
                    target,
                    target,
                    self.smb_version,
                    self.username,
                    self.password,
                    self.domain,
                    self.lmhash,
                    self.nthash,
                    self.aesKey,
                    self.dc_ip,
                    self.k,
                    self.debug
                ))
                instance_id += 1

            # Block until all tasks are done
            self.task_q.join()

        except KeyboardInterrupt as e:
            print("Quitting.")


class WebdavClientScanner:
    def __init__(self, address, target_ip, smb_version, username, password, domain, lmhash, nthash, aesKey, dc_ip, k, debug):
        self.address = address
        self.target_ip = target_ip
        self.smb_version = smb_version
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.aesKey = aesKey
        self.dc_ip = dc_ip
        self.k = k
        self.debug = debug

    def run(self):
        try:
            smbClient = SMBConnection(self.address, self.target_ip, preferredDialect=self.smb_version, timeout=2)
            if self.k is True:
                smbClient.kerberosLogin(self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, self.dc_ip)
            else:
                smbClient.login(self.username, self.password, self.domain, self.lmhash, self.nthash)

            pwd = '\\*'
            for f in smbClient.listPath('IPC$', pwd):
                if f.get_longname() == 'DAV RPC SERVICE':
                    with lock:
                        print("[{}] {}RUNNING{}".format(self.address, COLORS.GREEN, COLORS.ENDC))
                    return True
            with lock:
                print("[{}] {}STOPPED{}".format(self.address, COLORS.RED, COLORS.ENDC))
            return False

        except Exception as e:
            if self.debug:
                import traceback
                with lock:
                    traceback.print_exc()
            if self.debug or not (isinstance(e, OSError) and 'timed out' in str(e)):
                with lock:
                    print(str(e))
            return False



