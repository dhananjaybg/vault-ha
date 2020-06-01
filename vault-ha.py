#!/usr/bin/env /usr/local/bin/python3

import json
import os
import pycurl
import re
from io import BytesIO

cluster_tokens = {}
vault_clusters = ["vault-west", "vault-east"]

def get_secret():

    global cluster_tokens

    with open("tokens_mem", "r") as fh_:
        cluster_tokens = json.load(fh_)

    for vserv in vault_clusters:
        if vserv not in cluster_tokens:
            if not get_token(vserv):
                continue
            else:
                break
        else:
            break

    for vserv in vault_clusters:

        secret = vault_call(vserv, "get")

        if secret == "Connection Failed":
            continue
        elif secret == 403:
            if get_token(vserv):
                secret = vault_call(vserv, "get")
                break
            else:
                continue
        elif secret == 404:
            continue
        else:
            break

    return secret


def get_token(vserv):

    vtoken = vault_call(vserv, "login")

    if not re.match(r"(^s.{25}$)", vtoken):
        return False
    else:
        cluster_tokens.update({vserv: vtoken})

    with open("tokens_mem", "w+") as fh_:
        json.dump(cluster_tokens, fh_)

    return True


def vault_call(vserv, vact):

    crl = pycurl.Curl()
    data = BytesIO()
    base_url = "https://" + vserv + ":8200/v1/"

    if vact == "login":
        vault_url = base_url + "auth/approle/login"
        role_id = os.environ.get("ROLE_ID")
        sec_id = os.environ.get("SEC_ID")
        login_data = json.dumps({"role_id": role_id, "secret_id": sec_id})
        crl.setopt(crl.POSTFIELDS, login_data)
    elif vact == "get":
        vault_url = base_url + "vaultron-kv-v2/data/myapp"
        vault_header = ["X-Vault-Token: " + cluster_tokens[vserv]]
        crl.setopt(crl.HTTPHEADER, vault_header)
    else:
        print("Invalid Option")
        exit()

    crl.setopt(crl.URL, vault_url)
    crl.setopt(crl.WRITEFUNCTION, data.write)

    try:
        crl.perform()
        resp_data = json.loads(data.getvalue())
        resp_code = crl.getinfo(pycurl.RESPONSE_CODE)
    except pycurl.error:
        crl.close()
        return "Connection Failed"

    crl.close()

    if resp_code != 200:
        return resp_code
    elif vact == "login":
        return resp_data["auth"]["client_token"]
    elif vact == "get":
        return resp_data["data"]["data"]
    else:
        return resp_data


print(get_secret())
