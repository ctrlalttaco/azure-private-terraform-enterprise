Ubuntu 16.04 Predix Security Benchmark
======================================

This ansible content will configure a Ubuntu 16.04 LTS machine to be compliant with Predix security controls.

This role **will make changes to the system** that could break things. This is not an auditing tool but rather a remediation tool to be used after an audit has been conducted. For compliance auditing, use a tool such as [nessus](https://www.tenable.com/products/nessus-vulnerability-scanner) or [CIS-CAT](https://learn.cisecurity.org/cis-cat-landing-page)

## IMPORTANT INSTALL STEP

This code is based on the [CIS Ubuntu 16 Benchmark v1.1.0 ](https://www.cisecurity.org/cis-benchmarks/).

Requirements
------------

You should carefully read through the tasks to make sure these changes will not break your systems before running this playbook.

Role Variables
--------------
There are many role variables defined in defaults/main.yml.

By default, many of the variables are turned off. Please review and adjust to meet your organizational requirements.

Note, a subset of controls were removed due to operational impact or organizational dependent variables. Those are listed [here](https://docs.google.com/spreadsheets/d/1hHbPDnm5WspzGt6F67_Dw2GgLA1E0-NCAsIGeHJLK7s/edit#gid=0)

Dependencies
------------

Ansible > 2.4

Example Playbook
-------------------------

```yaml
---
- name: Harden Server
  hosts: all
  become: yes

  roles:
    - cis_hardening
```

## Testing


License
-------

Copyright General Electric Company, All Rights Reserved

[Original source code](https://github.com/GSA/ansible-os-ubuntu-16/tree/c1fdfd599922232e9ec9c9a344af9c87e0ed67a5) is licensed as MIT
