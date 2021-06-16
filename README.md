# OpenXPKI role

OpenXPKI deploys and configures [OpenXPKI](https://www.openxpki.org) CA. OpenXPKI stores
its data in MariaDB database. Role allows to use OpenXPKI in master-backup HA environment

This README documents only the deployment of OpenXPKI via Ansible.
Most of actual OpenXPKI configuration is not covered here because it is very extensive.
You must be familiar with OpenXPKI [documentation](https://openxpki.readthedocs.io)
and OpenXPKI sample configuration before using this role.

## Database

**IMPORTANT!**

OpenXPKI does nothing to prepare MariaDB server. Administrator must setup the MariaDB
server before deploying the role.

OpenXPKI expect the MariaDB to be present on the same node as OpenXPKI installation.
It attempts to create `openxpki_database_name` database, `openxpki_database_user` database
user and populate the database with its schema. This behavior can be disabled with
`openxpki_database_create: false` option. You want to disable database creation if
database is available remotely. If you do so you must prepare the remote database manually.
Consult OpenXPKI docs for more information

### Variables

| Variable                   | Mandatory | Default value        | Description                          |
| -------------------------- | --------- | -------------------- | ------------------------------------ |
| openxpki_database_type     | no        | MariaDB              | Can be one of MariaDB, MySQL, PostgreSQL, Oracle and DB2. |
| openxpki_database_host     | no        | localhost            | FQDN or IP address of database host  |
| openxpki_database_port     | no        | 3306                 | Database server TCP port             |
| openxpki_database_create   | no        | true                 | Assumes MariaDB database on target node. Creates openxpki database, user and imports schema |
| openxpki_database_name     | no        | openxpki             | Database name                        |
| openxpki_database_user     | no        | openxpki             | Database access user                 |
| openxpki_database_password | yes       |                      | Database access user password        |


## Crypto

Configure `/etc/openxpki/config.d/system/crypto.yaml`.
Important for configuring default secret passphrase which decrypts DataVault
private key and private keys of the imported crypto tokens.

### Variables

| Variable                       | Mandatory | Default value | Description                          |
| ------------------------------ | --------- | ------------- | ------------------------------------ |
| openxpki_crypto_secret_default | no        | root          | Default password for private key decryption |


## CA certificates

Role does not create CA certificates for you. You must do it manually after you deploy
OpenXPKI to the target host. See section bellow.

### Configuring datavault certificate

Prepare the datavault key (All HA nodes):

```
mkdir -p /etc/openxpki/local/keys/
cp datavault.key /etc/openxpki/local/keys/vault-1.pem
chown openxpki /etc/openxpki/local/keys/vault-1.pem
chmod 400 /etc/openxpki/local/keys/vault-1.pem
```

Import datavault certificate (Single HA node):

```
openxpkiadm certificate import --file datavault.crt
```

Restart the OpenXPKI service and verify datavault is working (All HA nodes):

```
systemctl restart openxpkid.service
openxpkicli  get_token_info --arg alias=vault-1 --realm democa
```

### Importing the CA certificates


Import the Root CA certificate (Single HA node):

```
openxpkiadm certificate import --file root.crt
```

Import the issuing CA (Single HA node):

```
openxpkiadm alias --realm democa --token certsign --file democa-signer.crt --key democa-signer.pem
```

Import the SCEP service certificate (Single HA node):

```
openxpkiadm alias --realm democa --token scep --file scep.crt --key scep.pem
```

Verify all tokens (All HA nodes):

```
openxpkiadm alias --realm democa
```


## Realms

Configure OpenXPKI relams.

### Realm definition

OpenXPKI supports multiple isolated realms. Realms are configured via `openxpki_realms`
array of dictionaries. Every dictionary contains its own variables:

| Variable       | Mandatory | Default value         | Description                          |
| -------------- | --------- | --------------------- | ------------------------------------ |
| name           | yes       |                       | Short name of the realm. Use for directories |
| label          | yes       |                       | Descriptive name of the realm |
| baseurl        | yes       |                       | Realm URL |
| home_page_file | no        | pki_default_home.html | Name of the home page HTML file to be copied to the `{{ openxpki_static_web }}/{{ realm.name }}/home.html` path |
| crl_publishing | no        | false                 | Schedule daily cron task to run CRL publish workflow. Cron runs between 01:00 and 02:00 |

Example:

```yaml
- name: 'internal'
  label: 'Demo CA'
  baseurl: 'https://pki.company.cz'
  home_page_file: 'pki_default_home.html'
  crl_publishing: true
```

### Realm file generation

Realm configuration lives in `/etc/openxpki/config.d/realm/{{ realm.name }}/` directory.
All files in this directory are in YAML format. Therefore is quite simple to transfer
YAML dictionaries from Ansible vars right into OpenXPKI realms configuration files.

There is a default set of configuration located within `/etc/openxpki/config.d/realm.tpl/`.
It makes perfect sense to reuse most of the configuration from the default set.

Realm configuration creation process have three steps:

1. Create directories
2. Create symlinks
3. Create or copy configuration files

Use `openxpki_realm_dirs` array of dictionaries variable to create directories.
Use `openxpki_realm_links` array of dictionaries variable to create symlinks.
Use `openxpki_realm_files` array of dictionaries variable to create files.

Dictionary variables shared by all three arrays:

| Variable       | Mandatory | Default value         | Description |
| -------------- | --------- | --------------------- | ----------- |
| .path          | yes       |                       | Path relative to `/etc/openxpki/config.d/realm/{{ realm.name }}/`  |
| .realm         | no        | all realms            | List of realms in which directory, symlink or file will be created  |

Dictionary variables exclusive to `openxpki_realm_files`:

| Variable       | Mandatory | Default value | Description |
| -------------- | --------- | ------------- | ----------- |
| .content       | no        |               | YAML dictionary which will become the content of the new file create at `path`  |
| .file          | no        |               | Filename to be copied to the `path`.  |

Note `.content` and `.file` are mutually exclusive. You must use one of them but only one
of them not both.

**IMPORTANT** Please note Ansible can't change file type after it is created for the first
time. Directory cannot be converted to the symlink, symlink can't be replaced with a file,
etc. To change the type of the file, you have to manually delete it and let Ansible create
it with the new type.

#### Examples

Create `auth` directory within all realms. Create `est` directory only within realm `demo1`
Create `rpc` directory only within realm `demo2`.

```yaml
openxpki_realm_dirs:
  - path: 'auth'
  - path: 'est'
    realms:
      - 'demo1'
  - path: 'rpc'
    realms:
      - 'demo2'
```

1. Create file symlink `auth/roles.yaml` -> `/etc/openxpki/config.d/realm.tpl/auth/roles.yaml`
within all realms.
3. Create directory symlink `profile/template` -> `/etc/openxpki/config.d/realm.tpl/profile/template`
within all realms.
2. Create directory symlink `scep` -> `/etc/openxpki/config.d/realm.tpl/scep/`
within realm `demo1`

```yaml
openxpki_realm_links:
  - path: 'auth/roles.yaml'
  - path: 'profile/template'
  - path: 'scep'
    realms:
      - 'demo1'
```

1. Create file `notification/smtp.yaml` in all realms. Content is generate from YAML dictionary
provides as variable.
2. Let the Ansible copy the file `openxpki/certificate_enroll_scep.yaml`
to `workflow/def` within all realms.
3. Generate file `scep/wso.yaml` only for realm demo1
4. Generate file `profile/template/serial_number.yaml`. This file will be created in
   `/etc/openxpki/config.d/realm.tpl/profile/template` because `profile/template`
   from previous example is actually a symlink leading there.

```yaml
  - path: 'notification/smtp.yaml'
    content: '{{ openxpki_notifications_smtp }}'

  - path: 'workflow/def/certificate_enroll_scep.yaml'
    file: 'openxpki/certificate_enroll_scep.yaml'

  - path: 'scep/wso.yaml'
    content: '{{ openxpki_scep_wso }}'
    realms:
      - 'demo1'

  - path: 'profile/template/serial_number.yaml'
    content: '{{ openxpki_profile_template_serial_number }}'
```

### Authentication

#### Local users

If you want to create use local user accounts for Password authentication module you can
define them using `openxpki_local_users` array of dictionaries. Each dictionary
has following keys:

| Variable  | Mandatory | Default value | Description |
| --------- | --------- | ------------- | ----------- |
| .name     | yes       |               | Username    |
| .role     | yes       |               | Choose user role from the ones defined in `auth/roles.yaml`  |
| .password | yes       |               | Password hash. Create it with `openxpkiadm hashpwd` command |


User account information is store in `/home/pkiadm/userdb.yaml` file.

Example:

```yaml
openxpki_local_users:
  - name: user
    role: User
    password: "password"
  - name: raop
    role: RA Operator
    password: "password"
  - name: caop
    role: CA Operator
    password: "password"
```

Sample OpenXPKI Password configuration in realms `auth/connector.yaml`:

```yaml
openxpki_auth_connectors:
  userdb:
    class: Connector::Proxy::YAML
    LOCATION: /home/pkiadm/userdb.yaml

...
```

Sample OpenXPKI Password configuration in realms `auth/handler.yaml`:

```yaml
openxpki_auth_handlers:
  Local Password:
    type: Password
    label: Local Password
    description: I18N_OPENXPKI_CONFIG_AUTH_HANDLER_DESCRIPTION_PASSWORD
    user@: connector:auth.connector.userdb

...
```

#### LDAP

LDAP integration is configured completely within realm configuraion

Sample OpenXPKI LDAP configuration in realms `auth/connector.yaml`:

```yaml
openxpki_auth_connectors:
  company-ldap:
    class: 'Connector::Builtin::Authentication::LDAP'
    LOCATION: 'ldaps://ldap.url.tld'
    base: 'dc=company,dc=tld'
    binddn: 'cn=accessuser,ou=users,dc=company,dc=tld'
    password: 'password'
    filter: '(uid=[% LOGIN %])'

...
```

Sample OpenXPKI LDAP configuration in realms `auth/handler.yaml`:

```yaml
openxpki_auth_handlers:
  LDAP Auth:
      type: Connector
      label: Company LDAP
      description: I18N_OPENXPKI_CONFIG_AUTH_HANDLER_DESCRIPTION_PASSWORD
      role: User
      source@: connector:auth.connector.company-ldap

...
```


## Publishing

OpenXPKI can publish CA certificates and CRL files. `openxpki_publishing_dirs` array
of paths can be used by Ansible to prepare necessary export directories:

```yaml
openxpki_publishing_dirs:
  - '/srv/www/ca/root'
  - '/srv/www/ca/democa1'
  - '/srv/www/ca/democa2'
```

You need to configure the actual publishing within the OpenXPKI realm configuration.


### CA certificate publishing

CA certificates can be manually published using the command:

```
/usr/bin/openxpkicmd --realm <realm.name> ca_publish
```

### CRL certificate publishing

CRL certificates can be manually published using the command:

```
/usr/bin/openxpkicmd --realm <realm.name> crl_issuance
```

Periodic CRL publishing can be scheduled by the `crl_publishing` boolean within
realm definition. See `Realm definition` section above.


## Enrollment wrappers

OpenXPKI Community Edition has 3 wrappers for automated certificate enrollment:

- EST
- RPC
- SCEP

EST and RPC must be manually enabled using following variables.

| Variable             | Mandatory | Default value | Description |
| -------------------- | --------- | ------------- | ----------- |
| openxpki_est_enabled | yes       | false         | Enables EST certificate enrollment |
| openxpki_rpc_enabled | yes       | false         | Enables RST API certificate enrollment  |

### EST wrapper configuration

openxpki_est_server_configurations:
  - name: 'internal'
    realm: 'internal'
    servername: 'servers'

### SCEP wrapper configuration

SCEP wrapper can have multiple configurations located in `/etc/openxpki/scep/`.
Configuration is automatically chosen based on URL. For `http://scep.vhost.tld/scep/enroll1`
URL `/etc/openxpki/scep/enroll1.conf` file would be used if it existed. Fallback configuration
file is `/etc/openxpki/scep/default.conf`. For more information see `/usr/lib/cgi-bin/scep.fcgi`.

SCEP wrapper configuration are created using the `openxpki_scep_server_configurations`
array of dictionaries. Each dictionary can have following variables

| Variable             | Mandatory | Default value | Description |
| -------------------- | --------- | ------------- | ----------- |
| name                 | yes       |               | Name of the configuration file without file extension |
| realm                | yes       |               | SCEP wrapper configuration target realm |
| servername           | yes       |               | SCEP configuration file within realm to be used for SCEP enrollment: `scep/{{ item.servername }}.yaml`  |
| iprange              | no        | 0.0.0.0/0     | IPv4 range allowed to access this wrapper configuration |
| encryption_algorithm | no        | 3DES          | SCEP encryption alogorithm |
| hash_algorithm       | no        | SHA256        | SCEP hash alogorithm |

Example:

```yaml
openxpki_scep_server_configurations:
  - name: 'test'
    servername: 'test'
    realm: 'democa1'
    encryption_algorithm: 'AES256'
    hash_algorithm: 'SHA256'
    iprange: '0.0.0.0/0
```


## Webserver

### Virtual hosts

There are 3 Apache virtual hosts deployed by this role:

- PKI: OpenXPKI website + EST, RPC and API access
- SCEP: Access exclusivelly for SCEP clients
- CA: Provides CA certificates and CRL files

**Please note you must either define entire vhost configuration dictionary or use
Ansible hash_behaviour=merge**

#### PKI vhost

Using unsecured HTTP is highly discouraged. DocumentRoot is `/var/www/openxpki`.

Apache TLS client authentication is enabled by default for this virtualhost.
CA certificate and hash index are expected to be present in `/etc/ssl/client/ca/`.
CRL files and hash index link are expected to be present /etc/ssl/client/crl/.
Role meta dependency `logicworks_ca` takes care of this.

Configuration:

| Variable            | Mandatory | Default value    | Description |
| ------------------- | --------- | ---------------- | ----------- |
| openxpki_vhost_pki  | no        |                  | PKI vhost configuration dictionary |
| .enabled            | yes*      | true             | Enables the PKI vhost |
| .name               | yes*      | pki              | vhost identifier (used for file names) |
| .site_name          | yes*      | pki.example.com  | vhost ServerName |
| .aliases            | no        |                  | Array of vhost domain aliases |
| .admin_mail         | yes*      | {{ admin_mail }} | Web admin email address |
| .https_enabled      | yes*      | true             | Enables HTTPS |
| .https_letsencrypt  | yes*      | false            | Enabeles LE certificate configuration |
| .https_redirect     | yes*      | true             | Enables HTTP -> HTTPS redirect |
| .cert               | yes*      | snakeoil.pem     | Path to certificate file. Not used for LE certs |
| .key                | yes*      | snakeoil.key     | Path to private key file. Not used for LE certs |
| .chain              | no        |                  | Path to file containg rest of certificate chain. Not used for LE certs |
| .custom_access      | no        |                  | Custom Apache configuration for access control |

Example:

```yaml
openxpki_vhost_pki:
  enabled: true
  name: 'pki'
  site_name: 'pki.company.tld'
  admin_mail: '{{ admin_mail }}'
  https_enabled: true
  https_letsencrypt: false
  https_redirect: true
  cert: /path/to/cert.pem
  key: /path/to/key.pem
  custom_access: |
    Require local
    Require ip 192.168.5.0/24
```


#### SCEP vhost

Should be accessible only via HTTP. Nothing stopping you from enabling the HTTPS as well
and some SCEP clients might work over HTTPS but it is not supported by SCEP standard.

Configuration:

| Variable            | Mandatory | Default value    | Description |
| ------------------- | --------- | ---------------- | ----------- |
| openxpki_vhost_pki  | no        |                  | PKI vhost configuration dictionary |
| .enabled            | yes*      | true             | Enables the PKI vhost |
| .name               | yes*      | scep             | vhost identifier (used for file names) |
| .site_name          | yes*      | scep.example.com | vhost ServerName |
| .aliases            | no        |                  | Array of vhost domain aliases |
| .www_root           | yes*      | /var/www/scep    | DocumentRoot directory |
| .admin_mail         | yes*      | {{ admin_mail }} | Web admin email address |
| .https_enabled      | yes*      | false            | Enables HTTPS |
| .https_letsencrypt  | yes*      | false            | Enabeles LE certificate configuration |
| .https_redirect     | yes*      | false            | Enables HTTP -> HTTPS redirect |
| .cert               | yes*      | snakeoil.pem     | Path to certificate file. Not used for LE certs |
| .key                | yes*      | snakeoil.key     | Path to private key file. Not used for LE certs |
| .chain              | no        |                  | Path to file containg rest of certificate chain. Not used for LE certs |
| .custom_access      | no        |                  | Custom Apache configuration for access control |

#### CA vhost

Should be accessible via both HTTP and HTTPS. **Site Indexes are enable by default.**

Configuration:

| Variable            | Mandatory | Default value    | Description |
| ------------------- | --------- | ---------------- | ----------- |
| openxpki_vhost_pki  | no        |                  | PKI vhost configuration dictionary |
| .enabled            | yes*      | true             | Enables the PKI vhost |
| .name               | yes*      | ca               | vhost identifier (used for file names) |
| .site_name          | yes*      | ca.example.com   | vhost ServerName |
| .aliases            | no        |                  | Array of vhost domain aliases |
| .www_root           | yes*      | /srv/www/ca      | DocumentRoot directory |
| .admin_mail         | yes*      | {{ admin_mail }} | Web admin email address |
| .https_enabled      | yes*      | true             | Enables HTTPS |
| .https_letsencrypt  | yes*      | false            | Enabeles LE certificate configuration |
| .https_redirect     | yes*      | false            | Enables HTTP -> HTTPS redirect |
| .cert               | yes*      | snakeoil.pem     | Path to certificate file. Not used for LE certs |
| .key                | yes*      | snakeoil.key     | Path to private key file. Not used for LE certs |
| .chain              | no        |                  | Path to file containg rest of certificate chain. Not used for LE certs |
| .custom_access      | no        |                  | Custom Apache configuration for access control |


### OpenXPKI extra web files

Use `openxpki_static_web` variable to define directory why hold OpenXPKI static websites
such us realm home site.

Default directory is `'/var/www/static'

Use `openxpki_web_localconfig` dictionary to create `/var/www/openxpki/localconfig.yaml`
OpenXPKI website configuration.

Example:

```yaml
openxpki_web_localconfig:
  header: |-
    <h2>
        <a href="./#/"><img src="img/logo.png" class="toplogo"></a>
        &nbsp;
        <small>Logicworks PKI</small>
    </h2>
```
