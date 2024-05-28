"""Active Directory user account status exporter"""
# ---
# Prometheus exporter for Active Directory users (check Locked status & Time)
# https://github.com/rtzra/adusers_exporter
#
# Requirements:
# apt install python3-ldap python3-prometheus-client
# or
# pip3 install python3-ldap python3-prometheus-client
#
#  some err can try >  pip3 install prometheus-client

import os
import time
from datetime import datetime
import datetime as dt

# Python Prometheus client
from prometheus_client import start_http_server, Gauge, Counter

# LDAP
from ldap3 import Server, Connection, SUBTREE, SAFE_SYNC



class ADUserMetrics:
    """
    Representation of Prometheus metrics and loop to fetch and transform
    application metrics into Prometheus metrics.
    """

    def __init__(self, polling_interval_seconds, attr):
        self.polling_interval_seconds = polling_interval_seconds
        self.attr = attr
        self.ad_server = str(os.getenv("AD_SERVER"))
        self.ad_search_tree = str(os.getenv("AD_SEARCH_TREE"))
        self.ad_user = str(os.getenv("AD_USER"))
        self.ad_password = str(os.getenv("AD_PASSWORD"))
        # Check all Environments Variables
        if not self.ad_server:
            check_env("You need to set the AD_SERVER environment variable.")
        if not self.ad_search_tree:
            check_env("You need to set the AD_SEARCH_TREE environment variable.")
        if not self.ad_user:
            check_env("You need to set the AD_USER environment variable.")
        if not self.ad_password:
            check_env("You need to set the AD_PASSWORD environment variable.")
        self.users = []

        # Prometheus metrics with labels to collect
        self.ad_user_lockout_status = Gauge("ad_user_locked_out", "Account lockedOut status", labelnames=['cn'])
        self.ad_user_lockout_time = Gauge("ad_user_lockout_time", "Account lockout time (if exist)", labelnames=['cn'])

    def run_metrics_loop(self):
        """
        Metrics fetching loop
        """

        while True:
            self.fetch()
            time.sleep(self.polling_interval_seconds)

    def fetch(self):
        """
        1. Get metrics from Active Directory and refresh
        Prometheus metrics with new values.
        2. Updating user list before every time loop running
        """

        # Get status data from the Active Directory
        server = Server(self.ad_server)
        conn = Connection(server, user=self.ad_user, password=self.ad_password)
        try:
          conn.bind()
        except:
          print('Could not connect to server '+ self.ad_server)
          self.debug_info()
        # Update User List
        self.__updateUsers()
        for user in self.users:
            self.ad_filter = '(&(objectClass=user)(sAMAccountName=%s)(!(OU=resign)))'% (user)
            try:
                conn.search(self.ad_search_tree, self.ad_filter, SUBTREE, attributes=self.attr)
                #print(conn)
                # Check for non-existing user
                if not conn.entries:
                    print("User "+str(user)+" not found in "+ self.ad_server)
                # Check user attributes
                for entry in conn.entries:
                    user_cn = str(entry.cn)
                    islock = Islocked(str(entry.LockoutTime))
                    lockout_status = 0
                    lockout_time = 0
                    lt_posix = 0
                    if (entry.LockoutTime == None) or (str(entry.LockoutTime) == '1601-01-01 00:00:00+00:00'):
                        lockout_status = 0
                        lockout_time = 0
                        lt_posix = 0
                    else:
                        if islock == False :
                            lockout_status = 0
                        else :
                            lockout_status = 1
                        lockout_time = str(entry.LockoutTime)
                        lockout_time = lockout_time.split('.')[0]
                        lt_posix = datetime.strptime(lockout_time, '%Y-%m-%d %H:%M:%S').timestamp()
                    # Update Prometheus metrics with application metrics
                    self.ad_user_lockout_status.labels(user_cn).set(float(lockout_status))
                    self.ad_user_lockout_time.labels(user_cn).set(float(lt_posix))
            except (RuntimeError, TypeError, NameError)  as e :
                print(e)
                print(f"Could not get user: {user_cn} info from server "+ self.ad_server)
                self.debug_info()
        try:
            conn.unbind()
        except:
            self.debug_info()

    def __updateUsers(self):
        adUsers = self.__Get_Account_list()
        adUsers = adUsers.replace(" ", "").split(',')
        self.users = adUsers

    def __Get_Account_list(self):
        """
        Get All AD Account
        """
        server = Server(f"{self.ad_server}")
        try:
            server
        except:
            print("connection error")
        conn = Connection(server, f"{self.ad_user}", f"{self.ad_password}", client_strategy=SAFE_SYNC, auto_bind=True)
        base_dn = f"{self.ad_search_tree}"
        # Search Users Exclude Disabled Users
        result = conn.search(base_dn,  "(&(objectClass=user) (!(userAccountControl:1.2.840.113556.1.4.803:=2)) )")[2]
        ret = ""
        for x in result :
            name = x['raw_dn'].decode('utf-8').split(",")[0][3:]
            ret = ret + name + ", "
        # conn.unbind is for disconnection & new connection will get new account status
        conn.unbind()
        return ret[:-2]

    def debug_info(self, time_interval=""):
        """Debug info for troubleshooting"""

        print(str(datetime.now())+ " Debug info:")
        print(" AD Server: "+ str(self.ad_server))
        print(" Users list: "+ str(self.users))
        print(" Time_Interval: "+ time_interval)
        print("------")

def check_env(err_msg):
    """No defined environment variables, exiting """
    print(err_msg)
    exit(1)

def Islocked(time_text):
    if time_text == "[]" :
        return False
    timeuat = time_text.split("+")[0]
    try :
        format_time = dt.datetime.strptime(timeuat, '%Y-%m-%d %H:%M:%S.%f').replace(microsecond=0)
    except :
        format_time = dt.datetime.strptime(timeuat, '%Y-%m-%d %H:%M:%S')
    now_time = dt.datetime.now()
    interval_time = now_time - format_time
    if interval_time.days > 0 :
        return False
    elif interval_time.days <= 0 and interval_time.seconds/60 > 30 :
        return False
    else :
        return True

def main():
    """Main entry point"""

    # Define variables
    ad_guage = str(os.getenv("POLLING_INTERVAL_SECONDS"))
    polling_interval_seconds = int(ad_guage)
    attr=['cn','CanonicalName','sAMAccountName','LockoutTime','displayName','manager','lastLogon']

    app_metrics = ADUserMetrics(
        polling_interval_seconds=polling_interval_seconds,
        attr=attr,
    )

    # Start web-server
    print("----- Polling start -----")
    print(f"==== Guage Interval {polling_interval_seconds} Seconds =====")
    start_http_server(port=9111)
    app_metrics.run_metrics_loop()

if __name__ == "__main__":
    main()