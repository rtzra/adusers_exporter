"""Active Directory user account status exporter"""
# ---
# Prometheus exporter for Active Directory users (check Locked status & Time)
# https://github.com/rtzra/adusers_exporter
#
# Requirements:
#  apt install python3-ldap python3-prometheus-client
#   or
#  pip3 install python3-ldap python3-prometheus-client
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

    def __init__(self, polling_interval_seconds, ad_server, ad_search_tree, attr, ad_user, ad_password, users):
        self.polling_interval_seconds = polling_interval_seconds
        self.ad_server = ad_server
        self.ad_search_tree = ad_search_tree
        self.attr = attr
        self.ad_user = ad_user
        self.ad_password = ad_password
        self.users = users

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
        Get metrics from Active Directory and refresh
        Prometheus metrics with new values.
        """

        # Get status data from the Active Directory
        server = Server(self.ad_server)
        conn = Connection(server, user=self.ad_user, password=self.ad_password)
        try:
          conn.bind()
        except:
          print('Could not connect to server '+ self.ad_server)
          self.debug_info()

        for user in self.users:
          self.ad_filter = '(&(objectClass=user)(sAMAccountName=%s))'% (user)

          try:
            conn.search(self.ad_search_tree, self.ad_filter, SUBTREE, attributes=self.attr)

            # Check for non-existing user
            if not conn.entries:
              print("User "+str(user)+" not found in "+ self.ad_server)

            # Check user attributes
            for entry in conn.entries:
              user_cn = str(entry.cn)
              if (entry.LockoutTime == None) or (str(entry.LockoutTime) == '1601-01-01 00:00:00+00:00'):
                lockout_status = 0
                lockout_time = 0
                lt_posix = 0
              else:
                x = Islocked(str(entry.LockoutTime))
                if x == False :
                    lockout_status = 0
                    lockout_time = 0
                    lt_posix = 0
                else :
                    lockout_status = 1
                    lockout_time = str(entry.LockoutTime)
                    lockout_time = lockout_time.split('.')[0]
                    lt_posix = datetime.strptime(lockout_time, '%Y-%m-%d %H:%M:%S').timestamp()

            # Update Prometheus metrics with application metrics
            self.ad_user_lockout_status.labels(user_cn).set(float(lockout_status))
            self.ad_user_lockout_time.labels(user_cn).set(float(lt_posix))

          except:
              print(f"Could not get user: {user_cn} info from server "+ self.ad_server)
              self.debug_info()

        try:
          conn.unbind()
        except:
          self.debug_info()

    def debug_info(self):
        """Debug info for troubleshooting"""

        print(str(datetime.now())+ " Debug info:")
        print(" AD Server: "+ str(self.ad_server))
        print(" Search Tree: "+ str(self.ad_search_tree))
        print(" Attributes: "+ str(self.attr))
        print(" AD User: "+ str(self.ad_user))
        print(" Users list: "+ str(self.users))
        print("------")


def check_env(err_msg):
    """No defined environment variables, exiting """
    print(err_msg)
    exit(1)

###################################################
# customize functions                             #
# for loging AD Server & get user account list    #
###################################################
def Get_Account_list(name,passwd,ad_server,ad_search_tree):
    """
    Get All AD Account
    """
    server = Server(f"{ad_server}")
    try:
        server
    except:
        print("connection error")
    conn = Connection(server, f"{name}", f"{passwd}", client_strategy=SAFE_SYNC, auto_bind=True)
    base_dn = f"{ad_search_tree}"
    result = conn.search(base_dn,  "(&(objectClass=user))")[2]
    ret = ""
    for x in result :
        name = x['raw_dn'].decode('utf-8').split(",")[0][3:]
        if name[:3] == "nap" :
            name = "nap"
            ret = ret + name + ", "
        else :
            ret = ret + name + ", "
    return ret[:-2]



def Islocked(time_text):
    timeuat = time_text
    format_time = dt.datetime.strptime(timeuat[:-6], '%Y-%m-%d %H:%M:%S.%f')
    format_time = format_time + dt.timedelta(hours=8)
    now_time = dt.datetime.now()
    interval_time = now_time - format_time
    if interval_time.days >= 0 and interval_time.seconds/60 > 30 :
        return False
    else :
        return True


def main():
    """Main entry point"""
    # Define variables
    ad_guage = str(os.getenv("POLLING_INTERVAL_SECONDS"))
    exporter_port = int(os.getenv("EXPORTER_PORT", "9111"))
    polling_interval_seconds = int(os.getenv("POLLING_INTERVAL_SECONDS", f"{ad_guage}"))
    attr=['cn','CanonicalName','sAMAccountName','LockoutTime','displayName','manager','lastLogon']
    ad_server = str(os.getenv("AD_SERVER"))
    ad_search_tree = str(os.getenv("AD_SEARCH_TREE"))
    ad_user = str(os.getenv("AD_USER"))
    ad_password = str(os.getenv("AD_PASSWORD"))
    # Define for user account list
    ad_query_users = Get_Account_list(ad_user, ad_password, ad_server, ad_search_tree)

    # Check all variables
    if not ad_server:
        check_env("You need to set the AD_SERVER environment variable.")
    if not ad_search_tree:
        check_env("You need to set the AD_SEARCH_TREE environment variable.")
    if not ad_user:
        check_env("You need to set the AD_USER environment variable.")
    if not ad_password:
        check_env("You need to set the AD_PASSWORD environment variable.")
    if not ad_query_users:
        check_env("You need to set the QUERY_USER environment variable.")

    # Split AD_QUERY_USER to Array
    ad_query_users = ad_query_users.replace(" ", "").split(',')

    app_metrics = ADUserMetrics(
        polling_interval_seconds=polling_interval_seconds,
        ad_server=ad_server,
        ad_search_tree=ad_search_tree,
        attr=attr,
        ad_user=ad_user,
        ad_password=ad_password,
        users=ad_query_users
    )

    # Start web-server
    start_http_server(exporter_port)
    app_metrics.run_metrics_loop()

if __name__ == "__main__":
    main()
