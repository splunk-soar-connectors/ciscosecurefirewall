# File: ciscosecurefirewall_connector.py
#
# Copyright (c) 2024 Splunk Inc.
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

import encryption_helper
import phantom.app as phantom
import requests
import simplejson as json
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from ciscosecurefirewall_consts import *


class FP_Connector(BaseConnector):

    def __init__(self):
        """
        Instance variables
        """
        # Call the BaseConnectors init first
        super(FP_Connector, self).__init__()

        self.username = ""
        self.password = ""
        self.firepower_host = ""
        self.headers = HEADERS
        self.verify = False

    def _reset_state_file(self):
        """
        This method resets the state file.
        """
        self.debug_print("Resetting the state file with the default format")
        self._state = {"app_version": self.get_app_json().get("app_version")}
        self.save_state(self._state)

    def initialize(self):
        """
        Initializes the global variables and validates them.

        This is an optional function that can be implemented by the
        AppConnector derived class. Since the configuration dictionary
        is already validated by the time this function is called,
        it's a good place to do any extra initialization of any internal
        modules. This function MUST return a value of either
        phantom.APP_SUCCESS or phantom.APP_ERROR.  If this function
        returns phantom.APP_ERROR, then AppConnector::handle_action
        will not get called.
        """
        self._state = self.load_state()
        config = self.get_config()
        action_result = ActionResult()

        if not isinstance(self._state, dict):
            self.debug_print(STATE_FILE_CORRUPT_ERR)
            self._reset_state_file()

        try:
            if TOKEN_KEY in self._state:
                self.debug_print("Decrypting the token")
                self._state[TOKEN_KEY] = encryption_helper.decrypt(self._state[TOKEN_KEY], self.get_asset_id())
        except Exception as e:
            self.debug_print("Error occurred while decrypting the token: {}".format(str(e)))
            self._reset_state_file()

        self.firepower_host = config["firepower_host"]
        self.username = config["username"]
        self.password = config["password"]
        self.verify = config.get("verify_server_cert", False)

        ret_val = self._get_token(action_result)
        if phantom.is_fail(ret_val):
            return self.get_status()

        return phantom.APP_SUCCESS

    def finalize(self):
        """
        Performs some final operations or clean up operations.

        This function gets called once all the param dictionary
        elements are looped over and no more handle_action calls are
        left to be made. It gives the AppConnector a chance to loop
        through all the results that were accumulated by multiple
        handle_action function calls and create any summary if
        required. Another usage is cleanup, disconnect from remote
        devices etc.
        """
        try:
            if TOKEN_KEY in self._state:
                self.debug_print("Encrypting the token")
                self._state[TOKEN_KEY] = encryption_helper.encrypt(self._state[TOKEN_KEY], self.asset_id)
        except Exception as e:
            self.debug_print("{}: {}".format(ENCRYPTION_ERR, str(e)))
            self._reset_state_file()

        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _update_state(self):
        """
        This method updates the state with the new values.
        """
        self._state[TOKEN_KEY] = self.token
        self._state[DOMAINS] = self.domains

    def _get_token(self, action_result):
        """
        This method returns the cached or a new token based
        on the values present in the state file.
        """
        self.token = self._state.get(TOKEN_KEY)

        if self.token:
            self.headers.update({"X-auth-access-token": self.token})
            return phantom.APP_SUCCESS

        # Generate a new token
        self.debug_print("Fetching a new token")
        self.generate_new_token = True
        ret_val, headers = self._api_run("post", TOKEN_ENDPOINT, action_result, headers_only=True, first_try=False)
        if phantom.is_fail(ret_val):
            self._reset_state_file()
            return action_result.get_status()

        self.token = headers.get("X-auth-access-token")

        try:
            self.domains = json.loads(headers.get("DOMAINS"))
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Received unexpected response from the server")

        self.headers.update({"X-auth-access-token": self.token})
        self._update_state()

        return phantom.APP_SUCCESS

    def _api_run(self, method, resource, action_result, json_body=None, headers_only=False, first_try=True, params=None):
        """
        This method makes a REST call to the API
        """
        request_method = getattr(requests, method)
        self.debug_print(f"host is {self.firepower_host} and resource is {resource}")
        url = "https://{0}{1}".format(self.firepower_host, resource)
        if json_body:
            self.headers.update({"Content-type": "application/json"})

        auth = None
        if self.generate_new_token:
            auth = requests.auth.HTTPBasicAuth(self.username, self.password)
            self.generate_new_token = False

        try:
            result = request_method(
                url, auth=auth, headers=self.headers, json=json_body, verify=self.verify, params=params, timeout=DEFAULT_REQUEST_TIMEOUT
            )
        except Exception as e:
            self.debug_print(f"problem here {e}")
            return action_result.set_status(phantom.APP_ERROR, "Error connecting to server. {}".format(str(e))), None

        self.debug_print(f"status code is {result.status_code}")
        if not (200 <= result.status_code < 399):
            if result.status_code == 401 and first_try:
                self._reset_state_file()
                ret_val = self._get_token(action_result)
                if phantom.is_fail(ret_val):
                    return action_result.get_status(), None

                return self._api_run(method, resource, action_result, json_body, headers_only, first_try=False)

            message = "Error from server. Status Code: {0} Data from server: {1}".format(
                result.status_code, result.text.replace("{", "{{").replace("}", "}}")
            )

            return action_result.set_status(phantom.APP_ERROR, message), None

        if headers_only:
            return phantom.APP_SUCCESS, result.headers

        resp_json = None
        try:
            resp_json = result.json()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. {0}".format(str(e))), None

        if not resp_json:
            return (
                action_result.set_status(phantom.APP_ERROR, f"Status code: {result.status_code}. Received empty response from the server"),
                None,
            )

        return phantom.APP_SUCCESS, resp_json

    def _handle_test_connectivity(self, param):
        """
        Called when the user presses the test connectivity
        button on the Phantom UI.
        """
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        self.save_progress("Testing connectivity")

        if self.token:
            self.save_progress("Connectivity test passed")
            return action_result.set_status(phantom.APP_SUCCESS)

        self.save_progress("Connectivity test failed")
        return action_result.set_status(phantom.APP_ERROR)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        return ret_val


if __name__ == "__main__":

    import sys

    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)

    # input a json file that contains data like the configuration and action parameters
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = FP_Connector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
