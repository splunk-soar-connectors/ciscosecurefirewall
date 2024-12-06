[comment]: # "Auto-generated SOAR connector documentation"
# Cisco Secure Firewall

Publisher: Splunk  
Connector Version: 1.0.0  
Product Vendor: Cisco Systems  
Product Name: Cisco Firepower  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.2.2  

This app interfaces with Cisco Firepower devices to add, update and delete network objects, network object groups, access policies and access rules

# Splunk> Phantom

Welcome to the open-source repository for Splunk> Phantom's ciscosecurefirewall App.

Please have a look at our [Contributing Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md) if you are interested in contributing, raising issues, or learning more about open-source Phantom apps.

## Legal and License

This Phantom App is licensed under the Apache 2.0 license. Please see our [Contributing Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md#legal-notice) for further details.


### Configuration Variables
This table lists the configuration variables required to operate Cisco Secure Firewall. These variables are specified when configuring a Cisco Firepower asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**firepower_host** |  required  | string | Device IP/Hostname
**verify_server_cert** |  optional  | boolean | Verify server certificate
**username** |  required  | string | User with access to the Firepower node
**password** |  required  | password | Password
**domain_name** |  optional  | string | Default firepower domain
**network_group_object** |  optional  | string | Default network group object

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[get network group objects](#action-get-network-group-objects) - Gets all network group objects in fmc host  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get network group objects'
Gets all network group objects in fmc host

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain_name** |  optional  | Firepower Domain. If none is specified the default domain will be queried | string | 

#### Action Output
No Output