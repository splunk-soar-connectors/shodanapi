# Shodan

Publisher: Splunk Community \
Connector Version: 1.0.1 \
Product Vendor: Shodan \
Product Name: Shodan Search Engine \
Minimum Product Version: 6.0.2

This app integrates with the Shodan Search engine. It supports search and on-demand scanning APIs

### Configuration variables

This table lists the configuration variables required to operate Shodan. These variables are specified when configuring a Shodan Search Engine asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api_key** | required | password | Shodan API Key |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration \
[search ip](#action-search-ip) - Returns all services that have been found on the given host IP \
[host count](#action-host-count) - Search Shodan without Results \
[search shodan](#action-search-shodan) - Search Shodan using the same query syntax as the website and use facets to get summary information for different properties \
[search parameter](#action-search-parameter) - List all search facets, filters \
[search token](#action-search-token) - Break the search query into tokens \
[scan ports](#action-scan-ports) - List all ports that Shodan is crawling on the Internet \
[scan protocols](#action-scan-protocols) - List all protocols that can be used when performing on-demand Internet scans via Shodan \
[scan ip only](#action-scan-ip-only) - Request Shodan to crawl an IP/ netblock \
[scan ip services](#action-scan-ip-services) - A pipe-separated list of IPs or netblocks (in CIDR notation) that should get crawled with services \
[scan internet](#action-scan-internet) - Crawl the Internet for a specific port and protocol using Shodan \
[scan status bulk](#action-scan-status-bulk) - Get list of all the created scans \
[shodan scan individual](#action-shodan-scan-individual) - Get the status of a scan request

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'search ip'

Returns all services that have been found on the given host IP

Type: **investigate** \
Read only: **True**

Parameters:
ip: [String] Host IP address
history (optional): [Boolean] True if all historical banners should be returned (default: False)
minify (optional): [Boolean] True to only return the list of ports and the general host information, no banners. (default: False).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | Host IP address | string | `ip` |
**history** | optional | True if all historical banners should be returned (default: False) | boolean | |
**minify** | optional | True to only return the list of ports and the general host information, no banners. (default: False) | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.history | boolean | | |
action_result.parameter.ip | string | `ip` | |
action_result.parameter.minify | boolean | | |
action_result.data.\*.area_code | string | | |
action_result.data.\*.asn | string | | |
action_result.data.\*.city | string | | |
action_result.data.\*.country_code | string | | |
action_result.data.\*.country_name | string | | |
action_result.data.\*.data | string | | |
action_result.data.\*.domains | string | | |
action_result.data.\*.hostnames | string | | |
action_result.data.\*.ip | numeric | | |
action_result.data.\*.ip_str | string | `ip` | |
action_result.data.\*.isp | string | | |
action_result.data.\*.last_update | string | | 1997-09-15T04:00:10.741612 |
action_result.data.\*.latitude | numeric | | |
action_result.data.\*.longitude | numeric | | |
action_result.data.\*.org | string | | |
action_result.data.\*.os | string | | |
action_result.data.\*.ports | numeric | | |
action_result.data.\*.region_code | string | | |
action_result.data.\*.tags | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'host count'

Search Shodan without Results

Type: **investigate** \
Read only: **True**

This method behaves identical to "/shodan/host/search" with the only difference that this method does not return any host results, it only returns the total number of results that matched the query and any facet information that was requested. As a result this method does not consume query credits.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** | required | Shodan search query. The provided string is used to search the database of banners in Shodan | string | |
**facets** | optional | A comma-separated list of properties to get summary information on | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.facets | string | | |
action_result.parameter.query | string | | |
action_result.data.\*.facet | string | | |
action_result.data.\*.facet_count | numeric | | |
action_result.data.\*.facet_value | string | | |
action_result.summary.total | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'search shodan'

Search Shodan using the same query syntax as the website and use facets to get summary information for different properties

Type: **investigate** \
Read only: **True**

Requirements
This method may use API query credits depending on usage. If any of the following criteria are met, your account will be deducted 1 query credit:

1. The search query contains a filter.
1. Accessing results past the 1st page using the "page". For every 100 results past the 1st page 1 query credit is deducted.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** | required | Shodan search query | string | |
**facets** | optional | A comma-separated list of properties to get summary information on | string | |
**page** | optional | The page number to page through results 100 at a time (default: 1) | numeric | |
**minify** | optional | Whether or not to truncate some of the larger fields (default: True) | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.facets | string | | |
action_result.parameter.minify | boolean | | |
action_result.parameter.page | numeric | | |
action_result.parameter.query | string | | |
action_result.data.\*.\_shodan.crawler | string | | |
action_result.data.\*.\_shodan.id | string | | |
action_result.data.\*.\_shodan.module | string | | |
action_result.data.\*.\_shodan.options.hostname | string | | |
action_result.data.\*.\_shodan.options.scan | string | | |
action_result.data.\*.\_shodan.ptr | string | | |
action_result.data.\*.\_shodan.region | string | | |
action_result.data.\*.asn | string | | |
action_result.data.\*.cloud.provider | string | | |
action_result.data.\*.cloud.region | string | | |
action_result.data.\*.cloud.service | string | | |
action_result.data.\*.cpe | array | | |
action_result.data.\*.cpe23 | array | | |
action_result.data.\*.domains | array | | |
action_result.data.\*.hash | numeric | | |
action_result.data.\*.hostnames | array | | |
action_result.data.\*.info | string | | |
action_result.data.\*.ip | numeric | | |
action_result.data.\*.ip_str | string | | |
action_result.data.\*.ipv6 | string | | |
action_result.data.\*.isp | string | | |
action_result.data.\*.location.area_code | string | | |
action_result.data.\*.location.city | string | | |
action_result.data.\*.location.country_code | string | | |
action_result.data.\*.location.country_name | string | | |
action_result.data.\*.location.latitude | numeric | | |
action_result.data.\*.location.longitude | numeric | | |
action_result.data.\*.location.region_code | string | | |
action_result.data.\*.org | string | | |
action_result.data.\*.os | string | | |
action_result.data.\*.port | numeric | | |
action_result.data.\*.product | string | | |
action_result.data.\*.tags | array | | |
action_result.data.\*.timestamp | string | | 1997-09-15T04:00:10.741612 |
action_result.data.\*.transport | string | | |
action_result.data.\*.version | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'search parameter'

List all search facets, filters

Type: **investigate** \
Read only: **True**

This method returns a list of facets that can be used to get a breakdown of the top values for a property or search filters that can be used in the search query.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**parameter_to_search** | required | Select parameter from dropdown | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.parameter_to_search | string | | |
action_result.data | array | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'search token'

Break the search query into tokens

Type: **investigate** \
Read only: **True**

This method lets you determine which filters are being used by the query string and what parameters were provided to the filters.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** | required | Shodan search query. The provided string is used to search the database of banners in Shodan | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.query | string | | |
action_result.data.\*.attributes | object | | |
action_result.data.\*.errors | array | | |
action_result.data.\*.filters | array | | |
action_result.data.\*.string | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'scan ports'

List all ports that Shodan is crawling on the Internet

Type: **investigate** \
Read only: **True**

This method returns a list of port numbers that the crawlers are looking for.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.data | array | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'scan protocols'

List all protocols that can be used when performing on-demand Internet scans via Shodan

Type: **investigate** \
Read only: **True**

This method returns an object containing all the protocols that can be used when launching an Internet scan.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.data.\*.protocol_desc | string | | |
action_result.data.\*.protocol_name | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'scan ip only'

Request Shodan to crawl an IP/ netblock

Type: **investigate** \
Read only: **True**

Use this method to request Shodan to crawl a network.

Requirements
This method uses API scan credits: 1 IP consumes 1 scan credit. You must have a paid API plan (either one-time payment or subscription) in order to use this method.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_list** | required | A comma-separated list of IPs or netblocks (in CIDR notation) that should get crawled. ip_1,ip_2,...,ip_n | string | |
**force** | optional | Whether or not to force Shodan to re-scan the provided IPs. Only available to enterprise users | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.force | boolean | | |
action_result.parameter.ip_list | string | | |
action_result.data.\*.count | string | | |
action_result.data.\*.credits_left | string | | |
action_result.data.\*.id | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'scan ip services'

A pipe-separated list of IPs or netblocks (in CIDR notation) that should get crawled with services

Type: **investigate** \
Read only: **True**

By default, the Shodan crawlers will check all the standard ports it normally crawls. However, you can also provide the services, a specific list of ports/ protocols you'd like the crawlers to use. A service is defined as a [port, protocol] in this action.

This action requires a pipe-separated list of IP addresses along with their services.
Provide input to this action in the following format,

ip_1:[ip_1_service_1],[ip_1_service_2] | ip_2:[ip_2_service_1],[ip_2_service_2] | ...

example:
1.1.1.1: \[[53,dns-udp], [443, https]\] | 8.8.8.8: \[[53, dns-tcp]\] | 12.8.8.8: \[[53, dns-tcp]\].

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_with_services** | required | A pipe-separated list of IP addresses along with their services. ip_1:[ip_1_service_1],[ip_1_service_2] | ip_2:[ip_2_service_1],[ip_2_service_2] | and so on | string | |
**force** | optional | Whether or not to force Shodan to re-scan the provided IPs. Only available to enterprise users | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.force | boolean | | |
action_result.parameter.ip_with_services | string | | |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'scan internet'

Crawl the Internet for a specific port and protocol using Shodan

Type: **investigate** \
Read only: **True**

Use this method to request Shodan to crawl the Internet for a specific port.

Requirements
This method is restricted to security researchers and companies with a Shodan Enterprise Data license. To apply for access to this method as a researcher, please email jmath@shodan.io with information about your project. Access is restricted to prevent abuse.

Parameters
port: [Integer] The port that Shodan should crawl the Internet for.
protocol: [String] The name of the protocol that should be used to interrogate the port. See /shodan/protocols for a list of supported protocols.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**port** | required | The port that Shodan should crawl the Internet for | string | |
**protocol** | required | The name of the protocol that should be used to interrogate the port. See /shodan/protocols for a list of supported protocols | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.port | string | | |
action_result.parameter.protocol | string | | |
action_result.data.\*.id | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'scan status bulk'

Get list of all the created scans

Type: **investigate** \
Read only: **True**

Returns a listing of all the on-demand scans that are currently active on the account.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**page_number** | optional | From page number. Each page contains 100 scan results in it | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.page_number | string | | |
action_result.data.\*.matches.\*.created | string | | 2023-05-02T02:44:00.714000 |
action_result.data.\*.matches.\*.credits_left | numeric | | |
action_result.data.\*.matches.\*.id | string | | |
action_result.data.\*.matches.\*.size | numeric | | |
action_result.data.\*.matches.\*.status | string | | DONE QUEUE |
action_result.data.\*.matches.\*.status_check | string | | 2023-05-02T02:44:00.714000 |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'shodan scan individual'

Get the status of a scan request

Type: **investigate** \
Read only: **True**

Check the progress of a previously submitted scan request. Possible values for the status are:
SUBMITTING,
QUEUE,
PROCESSING,
DONE.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | The unique scan ID that was returned by /shodan/scan | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.id | string | | |
action_result.data.\*.count | string | | |
action_result.data.\*.created | string | | 2023-05-02T02:44:00.714000 |
action_result.data.\*.status | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
