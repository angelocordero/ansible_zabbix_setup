# ANSIBLE ZABBIX SETUP

Ansible playbook to setup zabbix agents / SNMP on hosts and add them to the server

## How to use
1. Clone the repo
2. Create an `inventory` file, example:
    ```
    [redhat]
    192.168.100.50 

    [redhat:vars]
    ansible_user=ansible
    ansible_password=changeme
    ansible_become=true
    ansible_become_user=root
    ansible_become_password=changeme

    [windows_servers]
    192.168.100.60

    [windows_servers:vars]
    ansible_user=ansible
    ansible_password=changeme
    ansible_connection=winrm
    ansible_port=5985
    ansible_winrm_scheme=http
    ansible_winrm_server_cert_validation=ignore
    ansible_winrm_transport=ntlm
    ```

3. Download relevant RPM and MSI Zabbix agent files and place them in their respective roles' files folder

    ```
    roles
    |--- zabbix-redhat
    |    |--- files
    |         |--- <put rpm file here>
    |
    |--- zabbix-windows
         |--- files
              |--- <put msi file here>
    ```

4. Double check all variables in the following files
    - `group_vars/all`
    - `roles/zabbix-redhat/vars/main.yml`
    - `roles/zabbix-windows/vars/main.yml`

## Versions
This playbook was written and tested on: 
- `ansible [core 2.14.17]`
- `zabbix_server (Zabbix) 7.0.10`

## License
Copyright © 2025 & onwards, John Angelo Cordero <johnangelocordero.dev@gmail.com>

All work within this project and repository is subject to the terms of the MIT license, which can be found in the [LICENSE](./LICENSE)