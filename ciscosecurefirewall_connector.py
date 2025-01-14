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

from typing import Any, Dict, Optional, Tuple

import encryption_helper
import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
import simplejson as json
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from ciscosecurefirewall_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


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
        self.default_firepower_domain = None
        self.refresh_count = 0

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

        self.fmc_type = config["fmc_type"]

        if self.is_cloud_deployment():
            ret_val = self.authenicate_cloud_fmc(config)
        else:
            self.asset_id = self.get_asset_id()
            try:
                if TOKEN_KEY in self._state:
                    self.debug_print("Decrypting the token")
                    self._state[TOKEN_KEY] = encryption_helper.decrypt(self._state[TOKEN_KEY], self.asset_id)
                if "domains" in self._state:
                    self.domains = self._state["domains"]
            except Exception as e:
                self.debug_print("Error occurred while decrypting the token: {}".format(str(e)))
                self._reset_state_file()

            self.firepower_host = config["firepower_host"]
            self.username = config["username"]
            self.password = config["password"]
            self.default_firepower_domain = config.get("domain_name")
            self.verify = config.get("verify_server_cert", False)
            self.refresh_token = self._state.get(REFRESH_COUNT, 0)

            ret_val = self._get_token(action_result)
            self.debug_print(f"the state file is {self._state}")

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
        self._state[REFRESH_TOKEN_KEY] = self.refresh_token
        self._state[REFRESH_COUNT] = self.refresh_count
        self._state[DOMAINS] = self.domains
        self.save_state(self._state)

    def authenicate_cloud_fmc(self, config):
        """
        This method updates the headers and sets the firepower host
        based on the users region.
        """
        region = config["region"]
        api_key = config["cloud_api_key"]
        self.firepower_host = CLOUD_HOST.format(region=region.lower())
        self.headers.update({"Authorization": f"Bearer {api_key}"})
        return phantom.APP_SUCCESS

    def _get_token(self, action_result):
        """
        This method returns the cached or a new token based
        on the values present in the state file.
        """
        self.token = self._state.get(TOKEN_KEY)

        if self.token:
            self.headers[TOKEN_KEY] = self.token
            return phantom.APP_SUCCESS

        # Use refresh token
        if REFRESH_TOKEN_KEY in self._state and self.refresh_count < 3:
            self.refresh_count += 1
            self.headers[REFRESH_TOKEN_KEY] = self._state[REFRESH_TOKEN_KEY]
            self.headers[TOKEN_KEY] = self._state[TOKEN_KEY]
            ret_val, headers = self._api_run("post", REFRESH_ENDPOINT, action_result, headers_only=True, first_try=False)
            if not phantom.is_fail(ret_val):
                self.token = headers.get(TOKEN_KEY)
                self.headers[TOKEN_KEY] = self.token
                self.headers.pop(REFRESH_TOKEN_KEY)
                self._update_state()
                return phantom.APP_SUCCESS

        # Generate a new token
        self.debug_print("Fetching a new token")
        self.headers.pop(REFRESH_TOKEN_KEY, None)
        auth = requests.auth.HTTPBasicAuth(self.username, self.password)
        ret_val, headers = self._api_run("post", TOKEN_ENDPOINT, action_result, headers_only=True, first_try=True, auth=auth)
        if phantom.is_fail(ret_val):
            self.debug_print(f"Error {ret_val} while generating token with response {headers}")
            self._reset_state_file()
            return action_result.get_status()

        self.token = headers.get(TOKEN_KEY)
        self.refresh_token = headers.get(REFRESH_TOKEN_KEY)
        self.refresh_count = 0

        try:
            self.domains = json.loads(headers.get("DOMAINS"))
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Received unexpected response from the server")

        self.headers.update({"X-auth-access-token": self.token})
        self._update_state()

        return phantom.APP_SUCCESS

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
            None,
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace("{", "{{").replace("}", "}}")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to parse JSON response. Error: {0}".format(str(e)),
                ),
                None,
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(r.status_code, r.text.replace("{", "{{").replace("}", "}}"))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        msg = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, msg), None)

    def _api_run(self, method, resource, action_result, json_body=None, headers_only=False, first_try=True, params=None, auth=None):
        """
        This method makes a REST call to the API
        """
        request_method = getattr(requests, method)
        url = "https://{0}{1}".format(self.firepower_host, resource)
        if json_body:
            self.headers.update({"Content-type": "application/json"})

        try:
            result = request_method(
                url, auth=auth, headers=self.headers, json=json_body, verify=self.verify, params=params, timeout=DEFAULT_REQUEST_TIMEOUT
            )
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error connecting to server. {}".format(str(e))), None

        if not (200 <= result.status_code < 399):
            if result.status_code == 401 and first_try:
                self._reset_state_file()
                if not self.is_cloud_deployment():
                    ret_val = self._get_token(action_result)
                    if phantom.is_fail(ret_val):
                        return action_result.get_status(), None

                self.debug_print(f"Running url that failed because of token error {resource}")
                return self._api_run(method, resource, action_result, json_body, headers_only, first_try=False)

            message = "Error from server. Status Code: {0} Data from server: {1}".format(
                result.status_code, result.text.replace("{", "{{").replace("}", "}}")
            )
            return action_result.set_status(phantom.APP_ERROR, message), None

        if headers_only:
            return phantom.APP_SUCCESS, result.headers

        return self._process_response(result, action_result)

    def is_cloud_deployment(self):
        return self.fmc_type == "Cloud"

    def _handle_test_connectivity(self, param: Dict[str, Any]) -> bool:
        """
        Called when the user presses the test connectivity
        button on the Phantom UI.
        """
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        self.save_progress("Testing connectivity")

        url = GET_HOSTS_ENDPOINT.format(domain_id="default")
        ret_val, _ = self._api_run("get", url, action_result)
        if phantom.is_fail(ret_val):
            self.save_progress("Connectivity test failed")
            return action_result.get_status()

        self.save_progress("Connectivity test passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def get_network_objects_of_type(self, object_type, domain_uuid, action_result, name=None):
        url = NETWORK_OBJECTS_ENDPOINT.format(domain_id=domain_uuid, type=object_type.lower() + "s")

        offset = 0
        limit = 50
        params = {"limit": limit}
        while True:
            params["offset"] = offset
            ret_val, response = self._api_run("get", url, action_result, params=params)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            try:
                network_obj_list = response.get("items", [])
                for item in network_obj_list:
                    if name and name != item["name"]:
                        continue

                    action_result.add_data(item)

            except Exception as e:
                message = "An error occurred while processing network objects"
                self.debug_print(f"{message}. {str(e)}")
                return action_result.set_status(phantom.APP_ERROR, str(e))

            if "paging" in response and "next" in response["paging"]:
                offset += limit
            else:
                break

        return phantom.APP_SUCCESS

    def _handle_list_network_objects(self, param: Dict[str, Any]) -> bool:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        domain_uuid = self.get_domain_id(param.get("domain_name"))
        obj_type = param.get("type")
        name = param.get("name")

        if obj_type:
            ret_val = self.get_network_objects_of_type(obj_type, domain_uuid, action_result, name)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        else:
            for object_type in OBJECT_TYPES:
                ret_val = self.get_network_objects_of_type(object_type, domain_uuid, action_result, name)
                if phantom.is_fail(ret_val):
                    return action_result.get_status()

        action_result.update_summary({"total_objects_returned": len(action_result.get_data())})

        return action_result.set_status(phantom.APP_SUCCESS)

    def get_network_object(self, domain_id: int, object_id: int) -> Tuple[bool, Dict[str, Any]]:
        url = NETWORK_OBJECT_ID_ENDPOINT.format(domain_id=domain_id, type="networks", object_id=object_id)
        ret_val, response = self._api_run("get", url, self)
        return ret_val, response

    def _handle_create_network_object(self, param: Dict[str, Any]) -> bool:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))
        name = param["name"]

        object_type = param["type"]
        payload = {"name": name, "type": object_type, "value": param["value"]}
        domain_uuid = self.get_domain_id(param.get("domain_name"))
        url = NETWORK_OBJECTS_ENDPOINT.format(domain_id=domain_uuid, type=object_type.lower() + "s")

        ret_val, response = self._api_run("post", url, action_result, json_body=payload)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary["Message"] = f"Successfully created network object with name {name}"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_network_object(self, param: Dict[str, Any]) -> bool:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))
        object_id = param["object_id"]
        domain_uuid = self.get_domain_id(param.get("domain_name"))
        ret_val, curent_object = self.get_network_object(domain_uuid, object_id)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        name = param.get("name") or curent_object["name"]
        object_type = param.get("type") or curent_object["type"]
        value = param.get("value") or curent_object["value"]
        payload = {"id": object_id, "name": name, "type": object_type, "value": value}

        url = NETWORK_OBJECT_ID_ENDPOINT.format(domain_id=domain_uuid, type=object_type.lower() + "s", object_id=object_id)

        ret_val, response = self._api_run("put", url, action_result, json_body=payload)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary["Message"] = f"Successfully updated network object with name {name}"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_network_object(self, param: Dict[str, Any]) -> bool:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))
        object_id = param["object_id"]
        object_type = param["type"]
        domain_uuid = self.get_domain_id(param.get("domain_name"))

        url = NETWORK_OBJECT_ID_ENDPOINT.format(domain_id=domain_uuid, type=object_type.lower() + "s", object_id=object_id)
        ret_val, response = self._api_run("delete", url, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary["Message"] = f"Successfully delete network object with id {object_id}"
        return action_result.set_status(phantom.APP_SUCCESS)

    def get_domain_id(self, domain_name: str) -> str:
        domain_name = domain_name or self.default_firepower_domain

        if not domain_name or self.is_cloud_deployment():
            return "default"

        for domain in self.domains:
            leaf_domain = domain["name"].lower().split('/')[-1]
            if domain_name.lower() == leaf_domain:
                return domain["uuid"]

    def _handle_get_network_groups(self, param: Dict[str, Any]) -> bool:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        group_name = param.get("group_name")
        domain_uuid = self.get_domain_id(param.get("domain_name"))

        url = NETWORK_GROUPS_ENDPOINT.format(domain_id=domain_uuid)

        offset = 0
        limit = 50
        params = {"limit": limit, "expanded": True}
        while True:
            params["offset"] = offset
            ret_val, response = self._api_run("get", url, action_result, params=params)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            try:
                network_group_list = response.get("items", [])
                for item in network_group_list:
                    if not group_name or group_name == item["name"]:
                        action_result.add_data({"name": item["name"], "uuid": item["id"]})

            except Exception as e:
                message = "An error occurred while processing network groups"
                self.debug_print(f"{message}. {str(e)}")
                return self.set_status(phantom.APP_ERROR, message)

            if "paging" in response and "next" in response["paging"]:
                offset += limit
            else:
                break

        action_result.update_summary({"total_groups_returned": len(action_result.get_data())})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_network_group(self, param: Dict[str, Any]) -> bool:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        group_name = param["name"]
        object_ids = param["network_object_ids"]
        objects = [{"id": item.strip()} for item in object_ids.split(",") if item.strip()]
        payload = {"name": group_name, "type": "NetworkGroup", "objects": objects}
        domain_uuid = self.get_domain_id(param.get("domain_name"))

        url = NETWORK_GROUPS_ENDPOINT.format(domain_id=domain_uuid)

        ret_val, response = self._api_run("post", url, action_result, json_body=payload)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary["Message"] = f"Successfully added network group with name {group_name}"
        return action_result.set_status(phantom.APP_SUCCESS)

    def get_network_group(self, domain_uuid, group_id):
        url = NETWORK_GROUPS_ID_ENDPOINT.format(domain_id=domain_uuid, group_id=group_id)
        ret_val, response = self._api_run("get", url, self)
        return ret_val, response

    def _handle_update_network_group(self, param: Dict[str, Any]) -> bool:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        group_id = param["network_group_id"]
        domain_uuid = self.get_domain_id(param.get("domain_name"))
        ret_val, resp = self.get_network_group(domain_uuid, group_id)
        if phantom.is_fail(ret_val):
            return self.get_status()

        if param.get("name"):
            resp["name"] = param["name"]

        current_network_objects = {obj["id"] for obj in resp.get("objects", [])}

        network_objects_to_add = param.get("network_object_ids_to_add", "")
        current_network_objects.update({item.strip() for item in network_objects_to_add.split(",") if item.strip()})

        network_objects_to_remove = param.get("network_object_ids_to_remove", "")
        current_network_objects.difference_update({item.strip() for item in network_objects_to_remove.split(",") if item.strip()})

        objects = [{"id": object_id} for object_id in current_network_objects]
        resp["objects"] = objects

        update_url = NETWORK_GROUPS_ID_ENDPOINT.format(domain_id=domain_uuid, group_id=group_id)
        ret_val, response = self._api_run("put", update_url, action_result, json_body=resp)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary["Message"] = f"Successfully update network group with id {group_id}"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_network_group(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        group_id = param["network_group_id"]
        domain_uuid = self.get_domain_id(param.get("domain_name"))

        update_url = NETWORK_GROUPS_ID_ENDPOINT.format(domain_id=domain_uuid, group_id=group_id)
        ret_val, response = self._api_run("delete", update_url, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary["Message"] = f"Successfully deleted network group with id {group_id}"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_access_policies(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))
        domain_uuid = self.get_domain_id(param.get("domain_name"))
        url = ACCESS_POLICY_ENDPOINT.format(domain_id=domain_uuid)

        offset = 0
        limit = 50
        params = {"limit": limit}
        while True:
            params["offset"] = offset
            ret_val, response = self._api_run("get", url, action_result, params=params)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            try:
                policies = response.get("items", [])
                for policy in policies:
                    action_result.add_data({"name": policy["name"], "policy_id": policy["id"]})

            except Exception as e:
                message = "An error occurred while processing access policies"
                self.debug_print(f"{message}. {str(e)}")
                return self.set_status(phantom.APP_ERROR, message)

            if "paging" in response and "next" in response["paging"]:
                offset += limit
            else:
                break

        action_result.update_summary({"total_policies_returned": len(action_result.get_data())})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_access_policy(self, param: Dict[str, Any]) -> bool:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))
        domain_uuid = self.get_domain_id(param.get("domain_name"))

        name = param["name"]
        payload = {"name": name, "type": "AccessPolicy", "defaultAction": {"action": param["action"].upper()}}
        if param.get("description"):
            payload["description"] = param["description"]

        url = ACCESS_POLICY_ENDPOINT.format(domain_id=domain_uuid)
        ret_val, response = self._api_run("post", url, action_result, json_body=payload)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary["Message"] = f"Successfully created access policy with name {name}"
        return action_result.set_status(phantom.APP_SUCCESS)

    def get_access_policy(self, domain_uuid, policy_id):
        url = ACCESS_POLICY_ID_ENDPOINT.format(domain_id=domain_uuid, policy_id=policy_id)
        ret_val, response = self._api_run("get", url, self)
        return ret_val, response

    def _handle_update_access_policy(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))
        domain_uuid = self.get_domain_id(param.get("domain_name"))

        policy_id = param["policy_id"]
        ret_val, policy_data = self.get_access_policy(domain_uuid, policy_id)
        if phantom.is_fail(ret_val):
            return self.get_status()

        cur_action = policy_data["defaultAction"]
        payload = {
            "id": policy_data["id"],
            "name": policy_data["name"],
            "type": "AccessPolicy",
            "defaultAction": cur_action,
            "description": policy_data.get("description", ""),
        }

        if param.get("name"):
            payload["name"] = param["name"]

        if param.get("description"):
            payload["description"] = param["description"]

        if param.get("action"):
            payload["defaultAction"]["action"] = param["action"].upper()

        url = ACCESS_POLICY_ID_ENDPOINT.format(domain_id=domain_uuid, policy_id=policy_id)
        print(f"payload is {payload}")
        ret_val, response = self._api_run("put", url, action_result, json_body=payload)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        print(f"updated policy with {response}")
        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary["Message"] = f"Successfully updated access policy with id {policy_id}"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_access_policy(self, param: Dict[str, Any]) -> bool:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))
        domain_uuid = self.get_domain_id(param.get("domain_name"))

        policy_id = param["policy_id"]

        url = ACCESS_POLICY_ID_ENDPOINT.format(domain_id=domain_uuid, policy_id=policy_id)
        ret_val, response = self._api_run("delete", url, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary["Message"] = f"Successfully deleted access policy with id {policy_id}"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_access_rules(self, param: Dict[str, Any]) -> bool:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))
        domain_uuid = self.get_domain_id(param.get("domain_name"))

        policy_id = param["policy_id"]
        rule_id = param.get("rule_id")

        if rule_id:
            ret_val, response = self.get_access_control_rule(domain_uuid, policy_id, rule_id)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            action_result.add_data(response)
            summary = action_result.update_summary({})
            summary["Message"] = f"Retrieved access rule with id {rule_id}"
            return action_result.set_status(phantom.APP_SUCCESS)

        url = ACCESS_RULES_ENDPOINT.format(domain_id=domain_uuid, policy_id=policy_id)

        offset = 0
        limit = 50
        params = {"limit": limit}
        while True:
            params["offset"] = offset
            ret_val, response = self._api_run("get", url, action_result, params=params)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            try:
                rules = response.get("items", [])
                for rule in rules:
                    action_result.add_data({"name": rule["name"], "rule_id": rule["id"]})

            except Exception as e:
                message = "An error occurred while processing access rules"
                self.debug_print(f"{message}. {str(e)}")
                return self.set_status(phantom.APP_ERROR, message)

            if "paging" in response and "next" in response["paging"]:
                offset += limit
            else:
                break

        action_result.update_summary({"total_rules_returned": len(action_result.get_data())})

        return action_result.set_status(phantom.APP_SUCCESS)

    def build_network_objects_list(self, network_ids: list, dommain_uuid: str) -> Tuple[bool, Optional[list]]:
        networks_objects = []
        for object_id in network_ids:
            ret_val, object_data = self.get_network_object(dommain_uuid, object_id)
            if not phantom.is_fail(ret_val):
                networks_objects.append({"type": object_data["type"], "id": object_id})
                continue
            ret_val, _ = self.get_network_group(dommain_uuid, object_id)
            if phantom.is_fail(ret_val):
                self.debug_print(f"Id {object_id} is not a network object or network group")
                return self.get_status(), None
            networks_objects.append({"type": "NetworkGroup", "id": object_id})

        return phantom.APP_SUCCESS, networks_objects

    def _handle_create_access_rules(self, param: Dict[str, Any]) -> bool:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))
        domain_uuid = self.get_domain_id(param.get("domain_name"))

        policy_id = param["policy_id"]
        name = param["name"]

        rule_payload = {
            "name": name,
            "action": param["action"],
            "enabled": param.get("enabled", False),
            "sourceNetworks": {"objects": []},
            "destinationNetworks": {"objects": []},
        }

        source_networks = param.get("source_networks", "")
        source_networks = [network.strip() for network in source_networks.split(",") if network.strip()]

        ret_val, source_networks_objects = self.build_network_objects_list(source_networks, domain_uuid)
        if phantom.is_fail(ret_val):
            return ret_val
        rule_payload["sourceNetworks"]["objects"] = source_networks_objects

        destination_networks = param.get("destination_networks", "")
        destination_networks = [network.strip() for network in destination_networks.split(",") if network.strip()]
        ret_val, destination_networks_objects = self.build_network_objects_list(destination_networks, domain_uuid)
        if phantom.is_fail(ret_val):
            return ret_val
        rule_payload["destinationNetworks"]["objects"] = destination_networks_objects

        url = ACCESS_RULES_ENDPOINT.format(domain_id=domain_uuid, policy_id=policy_id)
        ret_val, response = self._api_run("post", url, action_result, json_body=rule_payload)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary["Message"] = f"Successfully added access control rule with name {name} to policy {policy_id}"
        return action_result.set_status(phantom.APP_SUCCESS)

    def get_access_control_rule(self, domain_id: str, policy_id: str, rule_id: str) -> Tuple[bool, Dict[str, Any]]:
        url = ACCESS_RULES_ID_ENDPOINT.format(domain_id=domain_id, policy_id=policy_id, rule_id=rule_id)
        ret_val, response = self._api_run("get", url, self)
        return ret_val, response

    def _handle_update_access_rule(self, param: Dict[str, Any]) -> bool:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))
        domain_uuid = self.get_domain_id(param.get("domain_name"))
        rule_id = param["rule_id"]
        policy_id = param["policy_id"]

        ret_val, rule_data = self.get_access_control_rule(domain_uuid, policy_id, rule_id)
        if phantom.is_fail(ret_val):
            return self.get_status()

        rule_payload = {
            "id": rule_data["id"],
            "name": rule_data["name"],
            "action": rule_data["action"],
            "type": rule_data["type"],
            "enabled": rule_data["enabled"],
        }

        if param.get("name"):
            rule_payload["name"] = param["name"]

        if param.get("action"):
            rule_payload["action"] = param["action"]

        if param.get("enabled"):
            rule_payload["enabled"] = param["enabled"]

        current_source_networks = rule_data.get("destinationNetworks", {}).get("objects", [])
        source_networks = param.get("source_networks_to_add", "")
        source_networks = [network.strip() for network in source_networks.split(",") if network.strip()]
        ret_val, source_networks_objects = self.build_network_objects_list(source_networks, domain_uuid)
        if phantom.is_fail(ret_val):
            return ret_val
        current_source_networks.extend(source_networks_objects)
        current_source_networks_dic = {network["id"]: network for network in current_source_networks}
        source_networks_to_remove = param.get("source_networks_to_remove", "")
        source_networks_to_remove = [network.strip() for network in source_networks_to_remove.split(",") if network.strip()]

        filtered_source_networks = [value for key, value in current_source_networks_dic.items() if key not in source_networks_to_remove]
        rule_payload["sourceNetworks"] = {"objects": filtered_source_networks}

        current_destination_networks = rule_data.get("destinationNetworks", {}).get("objects", [])
        destination_networks = param.get("destination_networks_to_add", "")
        destination_networks = [network.strip() for network in destination_networks.split(",") if network.strip()]
        ret_val, destination_networks_objects = self.build_network_objects_list(destination_networks, domain_uuid)
        if phantom.is_fail(ret_val):
            return ret_val
        current_destination_networks.extend(destination_networks_objects)
        current_destination_networks_dic = {network["id"]: network for network in current_destination_networks}
        destination_networks_to_remove = param.get("destination_networks_to_remove", "")
        destination_networks_to_remove = [network.strip() for network in destination_networks_to_remove.split(",") if network.strip()]

        filtered_destination_networks = [
            value for key, value in current_destination_networks_dic.items() if key not in destination_networks_to_remove
        ]
        rule_payload["destinationNetworks"] = {"objects": filtered_destination_networks}

        url = ACCESS_RULES_ID_ENDPOINT.format(domain_id=domain_uuid, policy_id=policy_id, rule_id=rule_id)
        ret_val, response = self._api_run("put", url, action_result, json_body=rule_payload)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary["Message"] = f"Successfully updated access control rule with id {rule_id}"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_access_rule(self, param: Dict[str, Any]) -> bool:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))
        domain_uuid = self.get_domain_id(param.get("domain_name"))

        rule_id = param["rule_id"]
        policy_id = param["policy_id"]

        url = ACCESS_RULES_ID_ENDPOINT.format(domain_id=domain_uuid, policy_id=policy_id, rule_id=rule_id)
        ret_val, response = self._api_run("delete", url, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary["Message"] = f"Successfully delete access control rule with id {rule_id}"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_devices(self, param: Dict[str, Any]) -> bool:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))
        domain_uuid = self.get_domain_id(param.get("domain_name"))

        url = DEVICES_ENDPOINT.format(domain_id=domain_uuid)

        offset = 0
        limit = 50
        params = {"limit": limit}
        while True:
            params["offset"] = offset
            ret_val, response = self._api_run("get", url, action_result, params=params)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            try:
                devices = response.get("items", [])
                for device in devices:
                    action_result.add_data(device)

            except Exception as e:
                message = "An error occurred while getting devices"
                self.debug_print(f"{message}. {str(e)}")
                return action_result.set_status(phantom.APP_ERROR, message)

            if "paging" in response and "next" in response["paging"]:
                offset += limit
            else:
                break

        action_result.update_summary({"total_deices_returned": len(action_result.get_data())})

        return action_result.set_status(phantom.APP_SUCCESS)

    def get_deployable_devices(self, domain_id: str) -> Tuple[bool, Any]:
        url = GET_DEPLOYABLE_DEVICES_ENDPOINT.format(domain_id=domain_id, isExpand=True)
        deployable_devices = []
        offset = 0
        limit = 50
        params = {"limit": limit, "expanded": True}
        while True:
            params["offset"] = offset
            ret_val, response = self._api_run("get", url, self, params=params)
            if phantom.is_fail(ret_val):
                return phantom.APP_ERROR, []

            try:
                devices = response.get("items", [])
                for item in devices:
                    deployable_devices.append({"name": item["device"]["name"], "id": item["device"]["id"], "type": item["device"]["type"]})
            except Exception as e:
                message = "An error occurred while processing access rules"
                self.debug_print(f"{message}. {str(e)}")
                return phantom.APP_ERROR, []

            if "paging" in response and "next" in response["paging"]:
                offset += limit
            else:
                break

        return phantom.APP_SUCCESS, deployable_devices

    def _handle_get_deployable_devices(self, param: Dict[str, Any]) -> bool:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))
        domain_uuid = self.get_domain_id(param.get("domain_name"))

        ret_val, devices = self.get_deployable_devices(domain_uuid)

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, "Unable to get deployable devices")

        for device in devices:
            action_result.add_data(device)

        action_result.update_summary({"total_deployable_deices_returned": len(action_result.get_data())})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_deploy_devices(self, param: Dict[str, Any]) -> bool:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))
        domain_uuid = self.get_domain_id(param.get("domain_name"))

        devices_to_deploy = [device.strip() for device in param.get("devices", "").split(",") if device.strip()]
        if not devices_to_deploy:
            ret_val, devices = self.get_deployable_devices(domain_uuid)
            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, "Unable to get deployable devices")
            for device in devices:
                devices_to_deploy.append(device["id"])

        if not devices_to_deploy:
            summary = action_result.update_summary({})
            summary["Message"] = "No devices to deploy"
            return action_result.set_status(phantom.APP_SUCCESS)

        url = DEPLOY_DEVICES_ENDPOINT.format(domain_id=domain_uuid)
        body = {"type": "DeploymentRequest", "version": "0", "forceDeploy": True, "ignoreWarning": True, "deviceList": devices_to_deploy}

        ret_val, response = self._api_run("post", url, action_result, body)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary["Message"] = "Successfully deployed devices"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_deployment_status(self, param: Dict[str, Any]) -> bool:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))
        domain_uuid = self.get_domain_id(param.get("domain_name"))

        deployment_id = param["deployment_id"]

        url = DEPLOYMENT_STATUS_ENDPOINT.format(domain_id=domain_uuid, task_id=deployment_id)
        ret_val, response = self._api_run("get", url, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary["Message"] = f"Successfully retrieved status for deployment {deployment_id}"
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)
        elif action_id == "list_network_ojects":
            self._handle_list_network_objects(param)
        elif action_id == "create_network_object":
            self._handle_create_network_object(param)
        elif action_id == "update_network_object":
            self._handle_update_network_object(param)
        elif action_id == "delete_network_object":
            self._handle_delete_network_object(param)
        elif action_id == "get_network_groups":
            ret_val = self._handle_get_network_groups(param)
        elif action_id == "create_network_group":
            ret_val = self._handle_create_network_group(param)
        elif action_id == "update_network_group":
            ret_val = self._handle_update_network_group(param)
        elif action_id == "delete_network_group":
            ret_val = self._handle_delete_network_group(param)
        elif action_id == "get_access_policies":
            ret_val = self._handle_get_access_policies(param)
        elif action_id == "create_access_policy":
            ret_val = self._handle_create_access_policy(param)
        elif action_id == "update_access_policy":
            ret_val = self._handle_update_access_policy(param)
        elif action_id == "delete_access_policy":
            ret_val = self._handle_delete_access_policy(param)
        elif action_id == "get_access_rules":
            ret_val = self._handle_get_access_rules(param)
        elif action_id == "create_access_rules":
            ret_val = self._handle_create_access_rules(param)
        elif action_id == "update_access_rule":
            ret_val = self._handle_update_access_rule(param)
        elif action_id == "delete_access_rule":
            ret_val = self._handle_delete_access_rule(param)
        elif action_id == "list_devices":
            ret_val = self._handle_list_devices(param)
        elif action_id == "get_deployable_devices":
            ret_val = self._handle_get_deployable_devices(param)
        elif action_id == "deploy_devices":
            ret_val = self._handle_deploy_devices(param)
        elif action_id == "get_deployment_status":
            ret_val = self._handle_get_deployment_status(param)

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
