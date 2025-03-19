#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
import json
import requests

def get_zabbix_auth_token(zabbix_server_api_url, zabbix_server_user, zabbix_server_password ):
    headers = {
        "Content-Type": "application/json-rpc"
    }
    
    payload = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {
            "username": f"{zabbix_server_user}",
            "password": f"{zabbix_server_password}"
        },
        "id": 1,
    }
    
    response = requests.post(zabbix_server_api_url, headers=headers, data=json.dumps(payload))
    
    if response.status_code == 200:
        result = response.json()
        if 'result' in result:
            return result['result']
        else:
            raise ValueError("Failed to get auth token: {}".format(result.get('error', 'Unknown error')))
    else:
        raise ValueError("Failed to connect to Zabbix API: HTTP {}".format(response.status_code))
    
def get_group_id(zabbix_server_api_url, zabbix_host_type, auth_token):
    type_map = {
        'RHEL': 'Linux Devices',
        'Windows': 'Windows Devices',
        'Cisco': 'Cisco Network Device',
        'SNMP': 'SNMP Devices'
    }

    type_string = type_map.get(zabbix_host_type, '')

    headers = {
        'Content-Type': 'application/json-rpc'
    }

    payload = {
        "jsonrpc": "2.0",
        "method": "hostgroup.get",
        "params": {
            "output": ["groupid"],
            "filter": {
                "name": [f"{type_string}"]
            }
        },
        "auth": f"{auth_token}",
        "id": 1
    }

    response = requests.post(zabbix_server_api_url, headers=headers, data=json.dumps(payload))

    if response.status_code == 200:
        result = response.json()
        if 'result' in result:
            return result['result'][0]['groupid']
        else:
            raise ValueError("Failed to get auth token: {}".format(result.get('error', 'Unknown error')))
    else:
        raise ValueError("Failed to connect to Zabbix API: HTTP {}".format(response.status_code))
    
def get_template_id(zabbix_server_api_url, zabbix_host_type, auth_token):
    template_map = {
        'RHEL': 'Linux by Zabbix agent',
        'Windows': 'Windows by Zabbix agent',
    }

    template_name = template_map.get(zabbix_host_type, '')

    headers = {
        'Content-Type': 'application/json-rpc'
    }

    payload = {
        "jsonrpc": "2.0",
        "method": "template.get",
        "params": {
            "output": ["templateid"],
            "filter": {
                "name": [f"{template_name}"]
            }
        },
        "auth": f"{auth_token}",
        "id": 1
    }

    response = requests.post(zabbix_server_api_url, headers=headers, data=json.dumps(payload))

    if response.status_code == 200:
        result = response.json()
        if 'result' in result:
            return result['result'][0]['templateid']
        else:
            raise ValueError("Failed to get auth token: {}".format(result.get('error', 'Unknown error')))
    else:
        raise ValueError("Failed to connect to Zabbix API: HTTP {}".format(response.status_code))

def add_host_zabbix_agent(zabbix_server_api_url, zabbix_host_name, zabbix_host_ip, zabbix_host_type, zabbix_server_user, zabbix_server_password, zabbix_agent_port):    
    zabbix_auth_token = get_zabbix_auth_token(zabbix_server_api_url, zabbix_server_user, zabbix_server_password )
    group_id = get_group_id(zabbix_server_api_url, zabbix_host_type, zabbix_auth_token)
    template_id = get_template_id(zabbix_server_api_url, zabbix_host_type, zabbix_auth_token)

    headers = {
        'Content-Type': 'application/json-rpc'
    }

    payload = {
        "jsonrpc": "2.0",
        "method": "host.create",
        "params": {
            "host": f"{zabbix_host_name}",
            "interfaces": [
                {
                    "type": 1,
                    "main": 1,
                    "useip": 1,
                    "ip": f"{zabbix_host_ip}",
                    "dns": "",
                    "port": f"{zabbix_agent_port}",
                }
            ],
            "groups": [ 
                {
                    "groupid": f"{group_id}",
                }
            ],
            "templates": [
                {
                    "templateid": f"{template_id}"
                }
            ]
        },
        "auth": f"{zabbix_auth_token}",
        "id": 1
    }

    response = requests.post(zabbix_server_api_url, headers=headers, data=json.dumps(payload))

    if response.status_code == 200:
        result = response.json()
        if 'result' in result:
            return result['result']['hostids'][0];
        else:
            error_msg = result.get('error', 'Unknown Error')
            raise ValueError(f"Failed to add host: {error_msg}")
    else:
        raise ValueError(f"Failed to connect to Zabbix API: HTTP {response.status_code} - {response.text}")
    
def add_host_zabbix_snmp_v2(zabbix_server_api_url, zabbix_host_name, zabbix_host_ip, zabbix_host_type, zabbix_server_user, zabbix_server_password, zabbix_snmp_port, snmp_v2_community_string):
    zabbix_auth_token = get_zabbix_auth_token(zabbix_server_api_url, zabbix_server_user, zabbix_server_password )
    group_id = get_group_id(zabbix_server_api_url, zabbix_host_type, zabbix_auth_token)

    headers = {
        'Content-Type': 'application/json-rpc'
    }

    payload = {
        "jsonrpc": "2.0",
        "method": "host.create",
        "params": {
            "host": f"{zabbix_host_name}",
            "interfaces": [
                {
                    "type": 2,
                    "main": 1,
                    "useip": 1,
                    "ip": f"{zabbix_host_ip}",
                    "dns": "",
                    "port": f"{zabbix_snmp_port}",
                    "details": {
                        "version": 2,
                        "community": f"{snmp_v2_community_string}"
                    }
                }
            ],
            "groups": [ 
                {
                    "groupid": f"{group_id}",
                }
            ],
        },
        "auth": f"{zabbix_auth_token}",
        "id": 1
    }

    response = requests.post(zabbix_server_api_url, headers=headers, data=json.dumps(payload))

    if response.status_code == 200:
        result = response.json()
        if 'result' in result:
            return result['result']['hostids'][0];
        else:
            error_msg = result.get('error', 'Unknown Error')
            raise ValueError(f"Failed to add host: {error_msg}")
    else:
        raise ValueError(f"Failed to connect to Zabbix API: HTTP {response.status_code} - {response.text}")

def add_host_zabbix_snmp_v3(zabbix_server_api_url, zabbix_host_name, zabbix_host_ip, zabbix_host_type, zabbix_server_user, zabbix_server_password, zabbix_snmp_port, snmp_v3_security_name, snmp_v3_auth_protocol, snmp_v3_auth_passphrase, snmp_v3_priv_protocol, snmp_v3_priv_passphrase):
    zabbix_auth_token = get_zabbix_auth_token(zabbix_server_api_url, zabbix_server_user, zabbix_server_password )
    group_id = get_group_id(zabbix_server_api_url, zabbix_host_type, zabbix_auth_token)

    headers = {
        'Content-Type': 'application/json-rpc'
    }

    payload = {
        "jsonrpc": "2.0",
        "method": "host.create",
        "params": {
            "host": f"{zabbix_host_name}",
            "interfaces": [
                {
                    "type": 2,
                    "main": 1,
                    "useip": 1,
                    "ip": f"{zabbix_host_ip}",
                    "dns": "",
                    "port": f"{zabbix_snmp_port}",
                    "details": {
                        "version": 3,
                        "securityname": f"{snmp_v3_security_name}",
                        "securitylevel": 2,
                        "authprotocol": f"{snmp_v3_auth_protocol}",
                        "authpassphrase": f"{snmp_v3_auth_passphrase}",
                        "privprotocol": f"{snmp_v3_priv_protocol}",
                        "privpassphrase": f"{snmp_v3_priv_passphrase}"
                    }
                }
            ],
            "groups": [ 
                {
                    "groupid": f"{group_id}",
                }
            ],
        },
        "auth": f"{zabbix_auth_token}",
        "id": 1
    }

    response = requests.post(zabbix_server_api_url, headers=headers, data=json.dumps(payload))

    if response.status_code == 200:
        result = response.json()
        if 'result' in result:
            return result['result']['hostids'][0];
        else:
            error_msg = result.get('error', 'Unknown Error')
            raise ValueError(f"Failed to add host: {error_msg}")
            # raise ValueError(f"{snmp_v3_security_name}{snmp_v3_auth_protocol}{snmp_v3_auth_passphrase}{snmp_v3_priv_protocol}{snmp_v3_priv_passphrase}")
    else:
        raise ValueError(f"Failed to connect to Zabbix API: HTTP {response.status_code} - {response.text}")

def run_module():
    module_args = dict(
        zabbix_server_api_url = dict(type='str', required=True),
        zabbix_server_user = dict(type='str', required=True),
        zabbix_server_password = dict(type='str', required=True, no_log=True),
        zabbix_host_name = dict(type='str', required=True),
        zabbix_host_ip = dict(type='str', required=True),
        zabbix_host_type = dict(type='str', required=True),
        zabbix_interface_type = dict(type='int', required=True), # zabbix interface type: 1 = agent, 2 = SNMP

        zabbix_agent_port = dict(type='int', required=False),
        zabbix_snmp_port = dict(type='int', required=False),
        snmp_v2_community_string = dict(type='str', required=False),
        snmp_v3_security_name = dict(type='str', required=False),
        snmp_v3_auth_protocol = dict(type='int', required=False),
        snmp_v3_auth_passphrase = dict(type='str', required=False, no_log=True),
        snmp_v3_priv_protocol = dict(type='int', required=False),
        snmp_v3_priv_passphrase = dict(type='str', required=False, no_log=True),
        snmp_version = dict(type='int', required=False)
    )

    module = AnsibleModule(
        argument_spec = module_args,
        supports_check_mode = True
    )

    if module.check_mode:
        module.exit_json(changed=False)
    else:
        zabbix_server_api_url = module.params['zabbix_server_api_url'].strip()
        zabbix_server_user = module.params['zabbix_server_user'].strip()
        zabbix_server_password = module.params['zabbix_server_password'].strip()
        zabbix_host_name = module.params['zabbix_host_name'].strip()
        zabbix_host_ip = module.params['zabbix_host_ip'].strip()
        zabbix_host_type = module.params['zabbix_host_type'].strip()
        zabbix_interface_type = module.params['zabbix_interface_type']

    if zabbix_interface_type == 1:
        zabbix_agent_port = module.params.get('zabbix_agent_port', None)

        if zabbix_agent_port is None:
            module.fail_json(msg="Zabbix interface type is 1, Zabbix Agent, but Zabbix Agent port is not defined")

        try:
          zabbix_result_id = add_host_zabbix_agent(zabbix_server_api_url, zabbix_host_name, zabbix_host_ip, zabbix_host_type, zabbix_server_user, zabbix_server_password, zabbix_agent_port)
          result = {
                'changed': True,
                'result': 'Successfully added host to Zabbix',
                'hostname': f'{zabbix_host_name}',
                'type': f'{zabbix_host_type}',
                'ip': f'{zabbix_host_ip}',
                'ip': f'{zabbix_result_id}',
          }
          
          module.exit_json(msg='Successfully added host to Zabbix' )

        except ValueError as e:
            result = {
                'changed': False,
                'msg': f'{e}',
            }

            module.fail_json(**result)

    elif zabbix_interface_type == 2: # SNMP Interface
        zabbix_snmp_port = module.params.get('zabbix_snmp_port', None)
        snmp_version = module.params.get('snmp_version', None)

        if zabbix_snmp_port is None:
            module.fail_json(msg="Zabbix interface type is 2, SNMP, but Zabbix SNMP port is not defined")

        if snmp_version == 2: # SNMP v2
            snmp_v2_community_string = module.params.get('snmp_v2_community_string', None).strip()

            if snmp_v2_community_string is None:
                module.fail_json(msg="Zabbix interface type is 2, SNMP, but SNMP v2 Community String is not defined")

            try:
                zabbix_result_id = add_host_zabbix_snmp_v2(zabbix_server_api_url, zabbix_host_name, zabbix_host_ip, zabbix_host_type, zabbix_server_user, zabbix_server_password, zabbix_snmp_port, snmp_v2_community_string)
                result = {
                    'changed': True,
                    'result': 'Successfully added host to Zabbix',
                    'hostname': f'{zabbix_host_name}',
                    'type': f'{zabbix_host_type}',
                    'ip': f'{zabbix_host_ip}',
                    'ip': f'{zabbix_result_id}',
                }
          
                module.exit_json(msg='Successfully added host to Zabbix' )

            except ValueError as e:
                result = {
                    'changed': False,
                    'msg': f'{e}',
                }

                module.fail_json(**result)

        if snmp_version == 3: # SNMPV3
            snmp_v3_security_name = module.params.get('snmp_v3_security_name', None).strip()
            snmp_v3_auth_protocol = module.params.get('snmp_v3_auth_protocol', None)
            snmp_v3_auth_passphrase = module.params.get('snmp_v3_auth_passphrase', None).strip()
            snmp_v3_priv_protocol = module.params.get('snmp_v3_priv_protocol', None)
            snmp_v3_priv_passphrase = module.params.get('snmp_v3_priv_passphrase', None).strip()

            if snmp_v3_security_name is None:
                module.fail_json(msg="Zabbix interface type is 3, SNMP, but SNMP v2 Community Name is not defined")
            if snmp_v3_auth_protocol is None:
                module.fail_json(msg="Zabbix interface type is 3, SNMP, but SNMP v2 Community String is not defined")
            if snmp_v3_auth_passphrase is None:
                module.fail_json(msg="Zabbix interface type is 3, SNMP, but SNMP v2 Community String is not defined")
            if snmp_v3_priv_protocol is None:
                module.fail_json(msg="Zabbix interface type is 3, SNMP, but SNMP v2 Community String is not defined")
            if snmp_v3_priv_passphrase is None:
                module.fail_json(msg="Zabbix interface type is 3, SNMP, but SNMP v2 Community String is not defined")

            if snmp_v3_auth_protocol < 0 or snmp_v3_auth_protocol > 5:
                module.fail_json(msg=f"Unknown snmp v3 auth protocol value: {snmp_v3_auth_protocol}")

            if snmp_v3_priv_protocol < 0 or snmp_v3_priv_protocol > 5:
                module.fail_json(msg=f"Unknown snmp v3 priv protocol value: {snmp_v3_priv_protocol}")

            try:
                zabbix_result_id = add_host_zabbix_snmp_v3(zabbix_server_api_url, zabbix_host_name, zabbix_host_ip, zabbix_host_type, zabbix_server_user, zabbix_server_password, zabbix_snmp_port, snmp_v3_security_name, snmp_v3_auth_protocol, snmp_v3_auth_passphrase, snmp_v3_priv_protocol, snmp_v3_priv_passphrase)
                result = {
                    'changed': True,
                    'result': 'Successfully added host to Zabbix',
                    'hostname': f'{zabbix_host_name}',
                    'type': f'{zabbix_host_type}',
                    'ip': f'{zabbix_host_ip}',
                    'ip': f'{zabbix_result_id}',
                } 
          
                module.exit_json(msg='Successfully added host to Zabbix' )

            except ValueError as e:
                result = {
                    'changed': False,
                    'msg': f'{e}',
                }

                module.fail_json(**result)

        else:
            module.fail_json(msg=f"{snmp_version}: Unsupported SNMP Version")

    else:
        module.fail_json(msg=f"{zabbix_interface_type}: Unsupported Interface")

def main():
    run_module()

if __name__ == '__main__':
    main()