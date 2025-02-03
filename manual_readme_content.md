[comment]: # " File: README.md"
[comment]: # "Copyright (c) 2025 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""

This connector supports both cloud and on-prem delivered FMC. Below are the steps for connecting to both

## Connecting to a cloud delivered FMC

1. On Cisco Security Cloud Control navigate to User Management 
2. Create a new Api Only User with an Admin role
3. Copy the Api key and enter it in the "Api key for cloud delivered FMC" input box in the SOAR Asset Settings page
4. Specfiy Cloud for the type of FMC you are connecting to
5. Specify your region in the "Region your Cisco Security Cloud Control is deployed in" input box and click Save

## Connecting to an on-prem delivered FMC

1. On the SOAR asset setting page select On-prem for the type of FMC you are connecting to
2. Specify the device ip/hostname of your on-prem FMC along with the username and password used ot login to FMC

**Note** that you can optionally specify a default firepower domain that will be queried. You an overide this domain when running an action. In addition, cloud versions of FMC only support the default domain, to achieve multi tenancy you must use seperate tenants. 
