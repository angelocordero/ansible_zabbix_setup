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
        'Windows Server': 'Windows Devices',
        'Cisco': 'Cisco Network Device'
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
        'Windows Server': 'Windows by Zabbix agent',
        'Cisco': 'Cisco IOS by Angelo'
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

def add_host_to_zabbix(zabbix_server_api_url, zabbix_host_name, zabbix_host_ip, zabbix_host_type, zabbix_server_user, zabbix_server_password):
    zabbix_auth_token = get_zabbix_auth_token(zabbix_server_api_url, zabbix_server_user, zabbix_server_password )
    group_id = get_group_id(zabbix_server_api_url, zabbix_host_type, zabbix_auth_token)
    template_id = get_template_id(zabbix_server_api_url, zabbix_host_type, zabbix_auth_token)

    headers = {
        'Content-Type': 'application/json-rpc'
    }

    interfaces_map = {
        'Cisco': {
            "type": 2,
            "main": 1,
            "useip": 1,
            "ip": f"{zabbix_host_ip}",
            "dns": "",
            "port": 161,
            "details": {
                "version": 2,
                "community": "public"
            }
        },
        'Default': {
            "type": 1,
            "main": 1,
            "useip": 1,
            "ip": f"{zabbix_host_ip}",
            "dns": "",
            "port": 10050
        }
    }

    interface = interfaces_map.get(type, interfaces_map['Default'])

    payload = {
        "jsonrpc": "2.0",
        "method": "host.create",
        "params": {
            "host": f"{zabbix_host_name}",
            "interfaces": [
                interface
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


def run_module():
    module_args = dict(
        zabbix_server_api_url = dict(type='str', required=True),
        zabbix_server_user = dict(type='str', required=True),
        zabbix_server_password = dict(type='str', required=True, no_log=True),
        zabbix_host_name = dict(type='str', required=True),
        zabbix_host_ip = dict(type='str', required=True),
        zabbix_host_type = dict(type='str', required=True),
    )

    module= AnsibleModule(
        argument_spec = module_args,
        supports_check_mode = True
    )

    if module.check_mode:
        module.exit_json(changed=False)
    else:
        zabbix_server_api_url = module.params['zabbix_server_api_url'].strip()
        zabbix_host_name = module.params['zabbix_host_name'].strip()
        zabbix_host_ip = module.params['zabbix_host_ip'].strip()
        zabbix_host_type = module.params['zabbix_host_type'].strip()
        zabbix_server_user = module.params['zabbix_server_user'].strip()
        zabbix_server_password = module.params['zabbix_server_password'].strip()

        try:
          zabbix_result_id = add_host_to_zabbix(zabbix_server_api_url, zabbix_host_name, zabbix_host_ip, zabbix_host_type, zabbix_server_user, zabbix_server_password)
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

def main():
    run_module()

if __name__ == '__main__':
    main()