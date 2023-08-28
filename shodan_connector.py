# File: shodan_connector.py
#
# Copyright (c) 2023 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

from __future__ import print_function, unicode_literals

import copy
import ipaddress
import json
import re

# Phantom App imports
import phantom.app as phantom
# Usage of the consts file is recommended
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
# External dependencies
from shodan import APIError, Shodan

from shodan_consts import *


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class ShodanConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(ShodanConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._api_key = None
        self._shodan_api = None
        self._api = None

    def _process_empty_response(self, response, action_result):
        if response.status_code in [200, 204]:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header, "
                                                        "Status code: {}".format(response.status_code)), None)

    def _process_html_response(self, response, action_result):
        # A html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(
                        str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        if (not kwargs['params']):
            kwargs['params'] = {}
        kwargs['params']['key'] = self._api_key

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get('verify_server_cert', False),
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(
                        str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint {0}".format(
            self._base_url + "/api-info"))

        ret_val, response = self._make_rest_call(
            '/api-info', action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success and display Shodan plan details
        self.save_progress("Plan - {0}".format(response['plan']))
        self.save_progress("Scan Credits - {0}".format(response['scan_credits']))
        self.save_progress("Query Credits - {0}".format(response['query_credits']))
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_search_ip(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        url_param = {}
        ip = param['ip']

        url_param['history'] = param.get('history', False)
        url_param['minify'] = param.get('minify', False)
        ret_val, response = self._make_rest_call(
            '/shodan/host/{0}'.format(ip), action_result, params=url_param, headers=None
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Some error occurred")
            action_result.set_status(phantom.APP_ERROR)

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_host_count(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        url_param = {}
        url_param['query'] = param['query']
        url_param['facets'] = param.get('facets', '')

        ret_val, response = self._make_rest_call(
            '/shodan/host/count', action_result, params=url_param, headers=None
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Some error occurred")
            action_result.set_status(phantom.APP_ERROR)

        if url_param['facets']:
            for key, value in response['facets'].items():
                temp_data = {}
                temp_data['facet'] = key
                for each in value:
                    temp_data['facet_value'] = each['value']
                    temp_data['facet_count'] = each['count']
                    action_result.add_data(copy.deepcopy(temp_data))

        summary = action_result.update_summary({})
        summary['total'] = response['total']
        msg = "Total host count {0}".format(response['total'])
        return action_result.set_status(phantom.APP_SUCCESS, msg)

    def _handle_search_shodan(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        url_param = {}
        url_param['query'] = param['query']
        url_param['facets'] = param.get('facets', '')
        url_param['page'] = param.get('page', 1)
        url_param['minify'] = param.get('minify', True)

        # make rest call
        ret_val, response = self._make_rest_call(
            '/shodan/host/search', action_result, params=url_param, headers=None
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Some error occurred")
            action_result.set_status(phantom.APP_ERROR)

        for each in response['matches']:
            action_result.add_data(each)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_search_parameter(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        parameter_to_search = param['parameter_to_search']

        ret_val, response = self._make_rest_call(
            '/shodan/host/search/{0}'.format(parameter_to_search), action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Some error occurred")
            action_result.set_status(phantom.APP_ERROR)

        action_result.add_data(response)

        msg = "Total {0} received: {1}".format(
            parameter_to_search, len(response))
        return action_result.set_status(phantom.APP_SUCCESS, msg)

    def _handle_search_token(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        url_param = {}
        url_param['query'] = param['query']
        ret_val, response = self._make_rest_call(
            '/shodan/host/search/tokens', action_result, params=url_param, headers=None
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Some error occurred")
            action_result.set_status(phantom.APP_ERROR)

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_scan_ports(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response = self._make_rest_call(
            '/shodan/ports', action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Some error occurred")
            action_result.set_status(phantom.APP_ERROR)

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['total'] = len(response)
        msg = "Total ports received: {0}".format(len(response))

        return action_result.set_status(phantom.APP_SUCCESS, msg)

    def _handle_scan_protocols(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # make rest call
        ret_val, response = self._make_rest_call(
            '/shodan/protocols', action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Some error occurred")
            action_result.set_status(phantom.APP_ERROR)

        for key, value in response.items():
            temp_protocol = {}
            temp_protocol['protocol_name'] = key
            temp_protocol['protocol_desc'] = value
            action_result.add_data(temp_protocol)

        summary = action_result.update_summary({})
        summary['total'] = len(response)
        msg = "Total protocols received: {0}".format(len(response))

        return action_result.set_status(phantom.APP_SUCCESS, msg)

    def is_valid_ip(self, ip):
        try:
            ip = ipaddress.ip_network(ip, False)
            return True
        except ValueError:
            self.save_progress(
                "Warning: IP {0} is not a valid IP. Ignoring!".format(ip))
        return False

    def process_ip_service_str(self, ip_services):
        ip_services = ((ip_services.replace(" ", '')).replace(
            "\"", '')).replace("'", '')

        def str_to_list(input_string):
            services_list = []
            pattern = r'\[\d+,[a-zA-Z0-9\-\s]+\]'
            result = re.findall(pattern, input_string)
            for each in result:
                lst = each.strip('[]').split(',')
                lst = [int(lst[0]), lst[1].strip()]
                services_list.append(lst)
            return services_list

        i_l = ip_services.split("|")
        result = {}
        for each in i_l:
            temp = each.split(":")
            if len(temp) == 2:
                result[temp[0]] = str_to_list(temp[1])

        return result

    def _handle_ip_only_scan(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ip_list = param['ip_list'].split(',')
        force_scan = param.get('force', False)

        ip_list = [x for x in ip_list if self.is_valid_ip(x)]

        if not ip_list:
            msg = 'No valid IP addresses found!'
            return action_result.set_status(phantom.APP_ERROR, msg)

        try:
            response = self._api.scan(ips=ip_list, force=force_scan)
            self.save_progress(
                "Submitted shodan scan with ips:{0}".format(",".join(ip_list)))
            ret_val, response = RetVal(phantom.APP_SUCCESS, response)
        except APIError as e:
            return action_result.set_status(phantom.APP_ERROR, str(e))

        if phantom.is_fail(ret_val):
            self.save_progress("Some error occurred")
            action_result.set_status(phantom.APP_ERROR)

        action_result.add_data(response)
        msg = "Scan submitted successfully with id {0}".format(response['id'])
        return action_result.set_status(phantom.APP_SUCCESS, msg)

    def _handle_scan_ip_with_services(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ip_with_services = param['ip_with_services']
        force_scan = param.get('force', False)
        ips = self.process_ip_service_str(ip_with_services)
        # check if the ips object has valid ip addresses.
        for each in list(ips.keys()):
            if not self.is_valid_ip(each):
                del ips[each]

        if not ips:
            msg = 'No valid IP addresses found!'
            return action_result.set_status(phantom.APP_ERROR, msg)

        try:
            response = self._api.scan(ips=ips, force=force_scan)
            self.save_progress(
                "Submitted shodan scan with ips:{0}".format(json.dumps(ips)))
            ret_val, response = RetVal(phantom.APP_SUCCESS, response)
        except APIError as e:
            self.save_progress(
                "Error: Error while submitting Shodan Scan {0}".format(str(e)))
            return action_result.set_status(phantom.APP_ERROR, str(e))

        if phantom.is_fail(ret_val):
            self.save_progress("Some error occurred")
            action_result.set_status(phantom.APP_ERROR)

        action_result.add_data(response)
        msg = "Scan submitted successfully with id {0}".format(response['id'])
        return action_result.set_status(phantom.APP_SUCCESS, msg)

    def _handle_scan_internet(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        port = param['port']
        protocol = param['protocol']

        try:
            port = int(port.strip())
            response = self._api.scan_internet(port=port, protocol=protocol)
            ret_val, response = RetVal(phantom.APP_SUCCESS, response)
        except APIError as e:
            self.save_progress(
                "Error: Error while submitting Shodan Scan {0}".format(str(e)))
            return action_result.set_status(phantom.APP_ERROR, str(e))
        except ValueError:
            error_msg = "Error: Invalid port number : {0}".format(port)
            self.save_progress(error_msg)
            return action_result.set_status(phantom.APP_ERROR, error_msg)

        if phantom.is_fail(ret_val):
            self.save_progress("Some error occurred")
            action_result.set_status(phantom.APP_ERROR)

        action_result.add_data(response)
        msg = "Scan submitted successfully with id {0}".format(response['id'])
        return action_result.set_status(phantom.APP_SUCCESS, msg)

    def _handle_scan_status_bulk(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        page_number = param.get('page_number', 1)

        try:
            page_number = int(page_number)
            response = self._api.scans(page=page_number)
            ret_val, response = RetVal(phantom.APP_SUCCESS, response)
        except APIError as e:
            self.save_progress(
                "Error: Error while getting Scan Status {0}".format(str(e)))
            return action_result.set_status(phantom.APP_ERROR, str(e))
        except ValueError:
            error_msg = "Error: Invalid page number : {0}".format(page_number)
            self.save_progress(error_msg)
            return action_result.set_status(phantom.APP_ERROR, error_msg)

        if phantom.is_fail(ret_val):
            self.save_progress("Some error occurred")
            action_result.set_status(phantom.APP_ERROR)

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary['total'] = response['total']
        msg = "Fetched {0} statuses on page number {1}".format(
            len(response['matches']), page_number)
        return action_result.set_status(phantom.APP_SUCCESS, msg)

    def _handle_shodan_scan_individual(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        id = param['id']

        try:
            response = self._api.scan_status(scan_id=id)
            ret_val, response = RetVal(phantom.APP_SUCCESS, response)
        except APIError as e:
            self.save_progress(
                "Error: Error while getting Scan Status {0}".format(str(e)))
            return action_result.set_status(phantom.APP_ERROR, str(e))

        if phantom.is_fail(ret_val):
            action_result.set_status(phantom.APP_ERROR)

        action_result.add_data(response)
        msg = "Fetched status for scan {0}. Scan status: {1}".format(
            id, response['status'])

        return action_result.set_status(phantom.APP_SUCCESS, msg)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'search_ip':
            ret_val = self._handle_search_ip(param)

        if action_id == 'host_count':
            ret_val = self._handle_host_count(param)

        if action_id == 'search_shodan':
            ret_val = self._handle_search_shodan(param)

        if action_id == 'search_parameter':
            ret_val = self._handle_search_parameter(param)

        if action_id == 'search_token':
            ret_val = self._handle_search_token(param)

        if action_id == 'scan_ports':
            ret_val = self._handle_scan_ports(param)

        if action_id == 'scan_protocols':
            ret_val = self._handle_scan_protocols(param)

        if action_id == 'ip_only_scan':
            ret_val = self._handle_ip_only_scan(param)

        if action_id == 'scan_ip_with_services':
            ret_val = self._handle_scan_ip_with_services(param)

        if action_id == 'scan_internet':
            ret_val = self._handle_scan_internet(param)

        if action_id == 'scan_status_bulk':
            ret_val = self._handle_scan_status_bulk(param)

        if action_id == 'shodan_scan_individual':
            ret_val = self._handle_shodan_scan_individual(param)

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = SHODAN_BASE_URL
        self._api_key = config.get(SHODAN_API_KEY)
        self._api = Shodan(self._api_key)

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = ShodanConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=SHODAN_DEFAULT_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, timeout=SHODAN_DEFAULT_TIMEOUT,
                               data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ShodanConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
