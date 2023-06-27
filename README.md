Shodan
======

Publisher: Splunk  
Contributors: N/A  
App Version: 1.1.0  
Product Vendor: Shodan  
Product Name: Shodan Search Engine  
Product Version Supported (regex): ".*"  

This app integrates with the Shodan Search engine. It supports search and on-demand scanning APIs.

tr.plain th { text-align: center; }

### Configuration Variables

The below configuration variables are required for this App to operate on **Shodan Search Engine**. These are specified when configuring an asset in Splunk SOAR.

| VARIABLE | REQUIRED | TYPE | DESCRIPTION |
| --- | --- | --- | --- |
| **API Key** | required | string | Shodan API Key |

### Supported Actions

[shodan scan individual](#) \- Get the status of a scan request  
[scan status bulk](#) \- Get list of all the created scans  
[scan internet](#) \- Crawl the Internet for a specific port and protocol using Shodan  
[scan ip with services](#) \- A pipe-separated list of IPs or netblocks (in CIDR notation) that should get crawled with services.  
[scan ip only](#) \- Request Shodan to crawl an IP/ netblock  
[scan protocols](#) \- List all protocols that can be used when performing on-demand Internet scans via Shodan.  
[scan ports](#) \- List all ports that Shodan is crawling on the Internet.  
[search token](#) \- Break the search query into tokens  
[search parameter](#) \- List all search facets, filters  
[search shodan](#) \- Search Shodan using the same query syntax as the website and use facets to get summary information for different properties.  
[host count](#) \- Search Shodan without Results  
[search ip](#) \- Returns all services that have been found on the given host IP.  
[test connectivity](#) \- Validate the asset configuration for connectivity using supplied configuration  

action: 'shodan scan individual'
--------------------------------

Get the status of a scan request

Type: **generic**

Read only: **True**

Check the progress of a previously submitted scan request. Possible values for the status are: SUBMITTING, QUEUE, PROCESSING, DONE.

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **id** | required | The unique scan ID that was returned by /shodan/scan. | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.parameter.id | string |     |     |
| action_result.status | string |     |     |
| action_result.data.*.status | string |     |     |
| action_result.data.*.created | string |     | 2023-05-02T02:44:00.714000 |
| action_result.data.*.count | string |     |     |
| action_result.message | string |     |     |

action: 'scan status bulk'
--------------------------

Get list of all the created scans

Type: **generic**

Read only: **True**

Returns a listing of all the on-demand scans that are currently active on the account.

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **page_number** | optional | From page number. Each page contains 100 scan results in it. | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action\_result.parameter.page\_number | string |     |     |
| action_result.status | string |     |     |
| action_result.data.*.matches.*.status | string |     | DONE  <br>QUEUE |
| action_result.data.*.matches.*.created | string |     | 2023-05-02T02:44:00.714000 |
| action\_result.data.*.matches.*.status\_check | string |     | 2023-05-02T02:44:00.714000 |
| action\_result.data.*.matches.*.credits\_left | numeric |     |     |
| action_result.data.*.matches.*.id | string |     |     |
| action_result.data.*.matches.*.size | numeric |     |     |
| action_result.message | string |     |     |
| summary.total_objects | numeric |     |     |
| summary.total\_objects\_successful | numeric |     |     |

action: 'scan internet'
-----------------------

Crawl the Internet for a specific port and protocol using Shodan

Type: **generic**

Read only: **False**

Use this method to request Shodan to crawl the Internet for a specific port. Requirements This method is restricted to security researchers and companies with a Shodan Enterprise Data license. To apply for access to this method as a researcher, please email jmath@shodan.io with information about your project. Access is restricted to prevent abuse. Parameters port: \[Integer\] The port that Shodan should crawl the Internet for. protocol: \[String\] The name of the protocol that should be used to interrogate the port. See /shodan/protocols for a list of supported protocols.

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **port** | required | The port that Shodan should crawl the Internet for. | string |     |
| **protocol** | required | The name of the protocol that should be used to interrogate the port. See /shodan/protocols for a list of supported protocols. | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.parameter.port | string |     |     |
| action_result.parameter.protocol | string |     |     |
| action_result.status | string |     |     |
| action_result.data.*.id | string |     |     |
| action_result.message | string |     |     |
| summary.total_objects | numeric |     |     |
| summary.total\_objects\_successful | numeric |     |     |

action: 'scan ip with services'
-------------------------------

A pipe-separated list of IPs or netblocks (in CIDR notation) that should get crawled with services.

Type: **generic**

Read only: **False**

By default, the Shodan crawlers will check all the standard ports it normally crawls. However, you can also provide the services, a specific list of ports/ protocols you'd like the crawlers to use. A service is defined as a \[port, protocol\] in this action. This action requires a pipe-separated list of IP addresses along with their services. Provide input to this action in the following format, ip\_1:\[ip\_1\_service\_1\],\[ip\_1\_service\_2\] | ip\_2:\[ip\_2\_service\_1\],\[ip\_2\_service\_2\] | ... example: 1.1.1.1: \[\[53,dns-udp\], \[443, https\]\] | 8.8.8.8: \[\[53, dns-tcp\]\] | 12.8.8.8: \[\[53, dns-tcp\]\]

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **force** | optional | Whether or not to force Shodan to re-scan the provided IPs. Only available to enterprise users. | boolean |     |
| **ip\_with\_services** | required | A pipe-separated list of IP addresses along with their services. ip\_1:\[ip\_1\_service\_1\],\[ip\_1\_service\_2\] \| ip\_2:\[ip\_2\_service\_1\],\[ip\_2\_service\_2\] \| ... | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action\_result.parameter.ip\_with_services | string |     |     |
| action_result.parameter.force | boolean |     |     |
| action_result.status | string |     |     |
| action_result.message | string |     |     |
| summary.total_objects | numeric |     |     |
| summary.total\_objects\_successful | numeric |     |     |

action: 'scan ip only'
----------------------

Request Shodan to crawl an IP/ netblock

Type: **generic**

Read only: **False**

Use this method to request Shodan to crawl a network. Requirements This method uses API scan credits: 1 IP consumes 1 scan credit. You must have a paid API plan (either one-time payment or subscription) in order to use this method.

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **force** | optional | Whether or not to force Shodan to re-scan the provided IPs. Only available to enterprise users. | boolean |     |
| **ip_list** | required | A comma-separated list of IPs or netblocks (in CIDR notation) that should get crawled. ip\_1,ip\_2,...,ip_n | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action\_result.parameter.ip\_list | string |     |     |
| action_result.parameter.force | boolean |     |     |
| action_result.status | string |     |     |
| action_result.data.*.id | string |     |     |
| action_result.data.*.count | string |     |     |
| action\_result.data.*.credits\_left | string |     |     |
| action_result.message | string |     |     |
| summary.total_objects | numeric |     |     |
| summary.total\_objects\_successful | numeric |     |     |

action: 'scan protocols'
------------------------

List all protocols that can be used when performing on-demand Internet scans via Shodan.

Type: **generic**

Read only: **False**

This method returns an object containing all the protocols that can be used when launching an Internet scan.

### Action Parameters

No parameters are required for this action

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     |     |
| action\_result.data.*.protocol\_name | string |     |     |
| action\_result.data.*.protocol\_desc | string |     |     |
| action_result.message | string |     |     |
| summary.total_objects | numeric |     |     |
| summary.total\_objects\_successful | numeric |     |     |

action: 'scan ports'
--------------------

List all ports that Shodan is crawling on the Internet.

Type: **generic**

Read only: **False**

This method returns a list of port numbers that the crawlers are looking for.

### Action Parameters

No parameters are required for this action

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     |     |
| action_result.data | array |     |     |
| action_result.message | string |     |     |
| summary.total_objects | numeric |     |     |
| summary.total\_objects\_successful | numeric |     |     |

action: 'search token'
----------------------

Break the search query into tokens

Type: **generic**

Read only: **False**

This method lets you determine which filters are being used by the query string and what parameters were provided to the filters.

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **query** | required | Shodan search query. The provided string is used to search the database of banners in Shodan | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.parameter.query | string |     |     |
| action_result.status | string |     |     |
| action_result.data.*.string | string |     |     |
| action_result.data.*.filters | array |     |     |
| action_result.data.*.errors | array |     |     |
| action_result.data.*.attributes | object |     |     |
| action_result.message | string |     |     |
| summary.total_objects | numeric |     |     |
| summary.total\_objects\_successful | numeric |     |     |

action: 'search parameter'
--------------------------

List all search facets, filters

Type: **generic**

Read only: **False**

This method returns a list of facets that can be used to get a breakdown of the top values for a property or search filters that can be used in the search query.

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **parameter\_to\_search** | required | Select parameter from dropdown | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action\_result.parameter.parameter\_to_search | string |     |     |
| action_result.status | string |     |     |
| action_result.data | array |     |     |
| action_result.message | string |     |     |
| summary.total_objects | numeric |     |     |
| summary.total\_objects\_successful | numeric |     |     |

action: 'search shodan'
-----------------------

Search Shodan using the same query syntax as the website and use facets to get summary information for different properties.

Type: **generic**

Read only: **False**

Requirements This method may use API query credits depending on usage. If any of the following criteria are met, your account will be deducted 1 query credit: 1. The search query contains a filter. 2. Accessing results past the 1st page using the "page". For every 100 results past the 1st page 1 query credit is deducted.

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **page** | optional | The page number to page through results 100 at a time (default: 1) | numeric |     |
| **query** | required | Shodan search query. | string |     |
| **facets** | optional | A comma-separated list of properties to get summary information on. | string |     |
| **minify** | optional | Whether or not to truncate some of the larger fields (default: True) | boolean |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.parameter.query | string |     |     |
| action_result.parameter.facets | string |     |     |
| action_result.parameter.page | numeric |     |     |
| action_result.parameter.minify | boolean |     |     |
| action_result.status | string |     |     |
| action_result.message | string |     |     |
| summary.total_objects | numeric |     |     |
| summary.total\_objects\_successful | numeric |     |     |
| action_result.data.*.ip | numeric |     |     |
| action_result.data.*.port | numeric |     |     |
| action_result.data.*.transport | string |     |     |
| action_result.data.*.hash | numeric |     |     |
| action_result.data.*.asn | string |     |     |
| action_result.data.*.os | string |     |     |
| action_result.data.*.tags | array |     |     |
| action_result.data.*.timestamp | string |     | 1997-09-15T04:00:10.741612 |
| action_result.data.*.isp | string |     |     |
| action_result.data.*.hostnames | array |     |     |
| action_result.data.*.domains | array |     |     |
| action_result.data.*.org | string |     |     |
| action\_result.data.*.ip\_str | string |     |     |
| action_result.data.*.cpe23 | array |     |     |
| action_result.data.*.cpe | array |     |     |
| action_result.data.*.product | string |     |     |
| action_result.data.*.version | string |     |     |
| action_result.data.*.info | string |     |     |
| action_result.data.*.ipv6 | string |     |     |
| action_result.data.*.cloud.region | string |     |     |
| action_result.data.*.cloud.service | string |     |     |
| action_result.data.*.cloud.provider | string |     |     |
| action_result.data.*.location.city | string |     |     |
| action\_result.data.*.location.region\_code | string |     |     |
| action\_result.data.*.location.area\_code | string |     |     |
| action_result.data.*.location.longitude | numeric |     |     |
| action_result.data.*.location.latitude | numeric |     |     |
| action\_result.data.*.location.country\_code | string |     |     |
| action\_result.data.*.location.country\_name | string |     |     |
| action\_result.data.*.\_shodan.region | string |     |     |
| action\_result.data.*.\_shodan.ptr | string |     |     |
| action\_result.data.*.\_shodan.module | string |     |     |
| action\_result.data.*.\_shodan.id | string |     |     |
| action\_result.data.*.\_shodan.crawler | string |     |     |
| action\_result.data.*.\_shodan.options.hostname | string |     |     |
| action\_result.data.*.\_shodan.options.scan | string |     |     |

action: 'host count'
--------------------

Search Shodan without Results

Type: **generic**

Read only: **False**

This method behaves identical to "/shodan/host/search" with the only difference that this method does not return any host results, it only returns the total number of results that matched the query and any facet information that was requested. As a result this method does not consume query credits.

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **query** | required | Shodan search query. The provided string is used to search the database of banners in Shodan. | string |     |
| **facets** | optional | A comma-separated list of properties to get summary information on. | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.parameter.query | string |     |     |
| action_result.parameter.facets | string |     |     |
| action_result.status | string |     |     |
| action_result.message | string |     |     |
| action_result.data.*.facet | string |     |     |
| action\_result.data.*.facet\_value | string |     |     |
| action\_result.data.*.facet\_count | numeric |     |     |
| action_result.summary.total | numeric |     |     |
| summary.total_objects | numeric |     |     |
| summary.total\_objects\_successful | numeric |     |     |

action: 'search ip'
-------------------

Returns all services that have been found on the given host IP.

Type: **generic**

Read only: **False**

Parameters: ip: \[String\] Host IP address history (optional): \[Boolean\] True if all historical banners should be returned (default: False) minify (optional): \[Boolean\] True to only return the list of ports and the general host information, no banners. (default: False)

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **ip** | required | Host IP address | string | ip  |
| **minify** | optional | True to only return the list of ports and the general host information, no banners. (default: False) | boolean |     |
| **history** | optional | True if all historical banners should be returned (default: False) | boolean |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.parameter.ip | string | ip  |     |
| action_result.parameter.history | boolean |     |     |
| action_result.parameter.minify | boolean |     |     |
| action_result.status | string |     |     |
| action_result.message | string |     |     |
| summary.total_objects | numeric |     |     |
| summary.total\_objects\_successful | numeric |     |     |
| action_result.data.*.city | string |     |     |
| action\_result.data.*.region\_code | string |     |     |
| action_result.data.*.os | string |     |     |
| action_result.data.*.ip | numeric |     |     |
| action_result.data.*.isp | string |     |     |
| action\_result.data.*.area\_code | string |     |     |
| action_result.data.*.longitude | numeric |     |     |
| action_result.data.*.latitude | numeric |     |     |
| action\_result.data.*.last\_update | string |     | 1997-09-15T04:00:10.741612 |
| action_result.data.*.ports | numeric |     |     |
| action_result.data.*.hostnames | string |     |     |
| action\_result.data.*.country\_code | string |     |     |
| action\_result.data.*.country\_name | string |     |     |
| action_result.data.*.domains | string |     |     |
| action_result.data.*.tags | string |     |     |
| action_result.data.*.org | string |     |     |
| action_result.data.*.asn | string |     |     |
| action\_result.data.*.ip\_str | string | ip  |     |
| action_result.data.*.data | object |     |     |

action: 'test connectivity'
---------------------------

Validate the asset configuration for connectivity using supplied configuration

Type: **test**

Read only: **True**

### Action Parameters

No parameters are required for this action

### Action Output

No Output
