#!/bin/bash

export EXPORTER_PORT="9111"
export POLLING_INTERVAL_SECONDS="60"
export AD_SERVER='ldaps://ldap.MYDOMAIN.COM'
export AD_SEARCH_TREE='DC=MYDOMAIN,DC=COM'
export AD_USER='ldap_account'
export AD_PASSWORD='SecretP@$$w0rd'
export AD_QUERY_USER='account1, account2, other_account3'

env | grep 'AD_'
