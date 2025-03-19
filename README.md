# ANSIBLE ZABBIX SETUP

Ansible playbook to setup zabbix agents / SNMP on hosts and add them to the server

## How to use
1. Clone the repo
2. Create an `inventory` file, example:
    ```
    [redhat]
    alma-01 ansible_host=192.168.100.50
    alma-02 ansible_host=192.168.100.51

    [windows]
    windows-test ansible_host=192.168.100.60

    [snmp]
    cisco-switch ansible_host=102.168.100.70

    [redhat:vars]
    ansible_user=ansible
    ansible_password=changeme
    ansible_become=true
    ansible_become_user=root
    ansible_become_password=changeme

    [windows:vars]
    ansible_user=ansible
    ansible_password=changeme
    ansible_connection=winrm
    ansible_port=5985
    ansible_winrm_scheme=http
    ansible_winrm_server_cert_validation=ignore
    ansible_winrm_transport=ntlm
    ```

3. Acquire the appropriate RPM and MSI Zabbix agent files, and store them in the designated "files" directories for their respective roles

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

4. Verify all variables thoroughly in the specified files
    - `group_vars/all.yml`
    - `group_vars/snmp.yml`
    - `roles/zabbix-redhat/vars/main.yml`
    - `roles/zabbix-windows/vars/main.yml`

## Roles
#### This Ansible playbook is structured with the following components:

- Zabbix agent configuration roles:
    - `zabbix-configure-redhat`
    - `zabbix-configure-windows`

- Playbook to add hosts to the server
    - `add-host-to-zabbix-server` (supports Zabbix Agent and SNMP monitoring)

#### Use cases:

- If Zabbix Agents require configuration, apply the relevant `zabbix-configure-* role`
- if Zabbix Agents are already configured, just use the `add-host-to-zabbix-server role to add the hosts to the Zabbix server

## Versions
This playbook was written and tested on: 
- `ansible [core 2.14.17]`
- `zabbix_server (Zabbix) 7.0.10`

## License
Copyright © 2025 & onwards, John Angelo Cordero <johnangelocordero.dev@gmail.com>

All work within this project and repository is subject to the terms of the MIT license, which can be found in the [LICENSE](./LICENSE)
