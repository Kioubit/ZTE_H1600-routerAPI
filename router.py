from enum import Enum
import re
import urllib
import urllib.request
import urllib.parse
import json
from hashlib import sha256
import xml.etree.ElementTree as xmlET
from collections.abc import Sequence


class RouterResponse:
    __response: str

    def __init__(self, response: str):
        self.__response = response

    def __str__(self):
        return self.__response

    def to_dict(self, xml_key: str = ""):
        root = xmlET.fromstring(self.__response)
        item = root
        if xml_key != "":
            item = root.find(xml_key)
        return _recursive_response_parse(item)

    def to_json(self, xml_key: str = "") -> str:
        return json.dumps(self.to_dict(xml_key))


def _recursive_response_parse(value: xmlET, depth: int = 0):
    if depth == 5:
        return ""
    temp_result = {}
    iterator = iter(value)
    did_pass = False
    for child in iterator:
        did_pass = True
        if child.tag == "ParaName":
            if child.text in temp_result:
                carry = temp_result.get(child.text)
                if isinstance(carry, Sequence):
                    temp_result[child.text].append(next(iterator).text)
                else:
                    temp_result[child.text] = [carry, next(iterator).text]
            else:
                temp_result[child.text] = next(iterator).text
        else:
            if child.tag in temp_result:
                carry = temp_result[child.tag]
                if isinstance(carry, Sequence):
                    temp_result[child.tag].append(_recursive_response_parse(child, depth + 1))
                else:
                    temp_result[child.tag] = [carry, _recursive_response_parse(child, depth + 1)]
            else:
                temp_result[child.tag] = _recursive_response_parse(child, depth + 1)
    if not did_pass:
        return value.text

    return temp_result


class ConnectionState(Enum):
    DISCONNECTED = 0
    CONNECTED = 1


class Router:
    state = ConnectionState.DISCONNECTED
    __base_url = ""
    __username = ""
    __password = ""
    # Session cookie
    __sess_id_cookie = ""
    # Except for login where it is returned in JSON it is found inside javascript on menuView requests
    __session_token = ""
    # Temporary CSRF token
    __session_token_by_post = ""
    __desired_menu = ""
    __current_menu = ""

    def __init__(self, base_url: str, username: str, password: str):
        self.__base_url = base_url
        self.__username = username
        self.__password = password

    def __make_request(self, url: str, save_session_cookie: bool = False, cookie: str = "", data: str|None = None) -> str:
        req = urllib.request.Request(url)
        if cookie:
            req.add_header("Cookie", cookie.partition(";")[0] + ";")
        if data:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("Check", sha256(data.encode()).hexdigest())
            response = urllib.request.urlopen(req, data=data.encode())
        else:
            response = urllib.request.urlopen(req)
        if response.getcode() != 200:
            raise Exception("HTTP Status code != 200")
        if save_session_cookie:
            cookies = response.info().get_all('Set-Cookie')
            for cookie in cookies:
                if cookie.startswith("SID="):
                    self.__sess_id_cookie = cookie
        page = response.read().decode("utf-8")
        return page

    def login(self):
        self.__current_menu = ""
        self.__sess_id_cookie = ""
        self.__session_token = ""
        login_entry_info = self.__make_request(self.__base_url + "?_type=loginData&_tag=login_entry",
                                               True, cookie=self.__sess_id_cookie)
        login_entry_info_json = json.loads(login_entry_info)
        locking_time = login_entry_info_json["lockingTime"]
        login_err_msg = login_entry_info_json["loginErrMsg"]
        if locking_time != 0:
            raise Exception("Locking time not zero: " + str(locking_time) + " " + login_err_msg)
        if login_err_msg != "":
            raise Exception("Login error message: " + login_err_msg)
        self.__session_token = login_entry_info_json["sess_token"]
        login_token_xml = self.__make_request(self.__base_url + "?_type=loginData&_tag=login_token",
                                              True, cookie=self.__sess_id_cookie)
        login_token_re = re.search('<ajax_response_xml_root>(.*)</ajax_response_xml_root>', login_token_xml)
        login_token = login_token_re.group(1)
        hashed_password = sha256(self.__password.encode() + login_token.encode()).hexdigest()
        login_string = "Password=" + hashed_password + "&Username=" + self.__username + "&_sessionTOKEN=" + \
                       self.__session_token + "&_sessionTOKENByPost=" + self.__session_token + "&action=login"
        login_result = json.loads(self.__make_request(self.__base_url + "?_type=loginData&_tag=login_entry",
                                                      True, self.__sess_id_cookie, login_string))
        self.__session_token = login_result["sess_token"]
        if "lockingTime" in login_result and "loginErrMsg" in login_result:
            locking_time = login_result["lockingTime"]
            login_err_msg = login_result["loginErrMsg"]
            if locking_time != 0:
                raise Exception("Locking time not zero: " + str(locking_time) + " " + login_err_msg)
            if login_err_msg != "":
                raise Exception("Login error message: " + login_err_msg)
        self.state = ConnectionState.CONNECTED

    def logout(self):
        if self.state == ConnectionState.DISCONNECTED:
            return
        final = "IF_LogOff=1&_sessionTOKEN=" + self.__session_token
        self.__make_request(self.__base_url + "?_type=loginData&_tag=logout_entry",
                            cookie=self.__sess_id_cookie, data=final)
        self.state = ConnectionState.DISCONNECTED
        self.__current_menu = ""
        self.__desired_menu = ""

    def __request_page(self, page: str, try_count: int = 0, is_query: bool = False, data: str|None = None) -> str:
        if self.state == ConnectionState.DISCONNECTED:
            raise Exception("Not connected")
        if try_count > 1:
            raise Exception("Failed to login after session expired")
        elif try_count == 1:
            self.login()
            if self.__current_menu != self.__desired_menu:
                self.enter_menu(self.__desired_menu)
        result = self.__make_request(self.__base_url + page, cookie=self.__sess_id_cookie, data=data)
        if result is not None and "<IF_ERRORSTR>SessionTimeout</IF_ERRORSTR>" in result:
            try_count += 1
            result = self.__request_page(page, try_count, is_query)
        if is_query and "<IF_ERRORSTR>SUCC</IF_ERRORSTR>" not in result:
            raise Exception("Error requesting page")
        if is_query:
            # only for queries returning <ajax_response_xml_root>
            result_r = xmlET.fromstring(result).find("./_sessionTmpTokenByPost")
            result_s = None
            if result_r is not None:
                result_s  = result_r.text
            if result_s is not None:
                self.__session_token_by_post = result_s
        if "?_type=menuView" in page:
            new_token = None
            for line in iter(result.splitlines()):
               if line.startswith("_sessionTmpToken"):
                   m = re.search("\"(.+?)\"", line)
                   if m:
                       new_token = m.group(1)
                   break
            if new_token is None:
               raise Exception("unable to find _sessionTmpToken")
            self.__session_token = bytes.fromhex(new_token.replace("\\x", "")).decode('utf-8')
        return result

    def request_page(self, page: str, is_query: bool = False) -> str:
        return self.__request_page(page=page, is_query=is_query)

    def enter_menu(self, menu: str):
        if self.__current_menu != menu:
            self.__request_page("?_type=menuView&_tag=" + menu + "&Menu3Location=0")
            self.__desired_menu = menu
            self.__current_menu = menu

    def __enter_menu_force(self, menu: str) -> str:
        self.__desired_menu = menu
        self.__current_menu = menu
        return self.__request_page("?_type=menuView&_tag=" + menu + "&Menu3Location=0")

    def request_stats(self) -> tuple[RouterResponse, RouterResponse]:
        self.enter_menu("dslWanStatus")
        dsl_stats = self.__request_page("?_type=menuData&_tag=dsl_interface_status_lua.lua", is_query=True)
        uplink_stats = self.__request_page("?_type=menuData&_tag=wan_internet_lua.lua&TypeUplink=1&pageType=1",
                                           is_query=True)
        return RouterResponse(dsl_stats), RouterResponse(uplink_stats)

    def request_dhcp4_info(self) -> RouterResponse:
        self.enter_menu("lanMgrIpv4")
        return RouterResponse(self.__request_page("?_type=menuData&_tag=dhcp4s_dhcphostinfo_m.lua", is_query=True))

    def request_firmware_info(self) -> RouterResponse:
        self.enter_menu("statusMgr")
        return RouterResponse(self.__request_page("?_type=menuData&_tag=devmgr_statusmgr_lua.lua", is_query=True))

    def restart(self):
        self.__enter_menu_force("statusMgr")
        self.__request_page("?_type=menuData&_tag=devmgr_statusmgr_lua.lua", is_query=True)
        self.__enter_menu_force("rebootAndReset")
        self.__request_page("?_type=menuData&_tag=devmgr_restartmgr_lua.lua", is_query=True, data=(
                    "IF_ACTION=Restart&Btn_restart=&_sessionTOKEN=" + self.__session_token +
                    "&_sessionTOKENByPost=" + self.__session_token_by_post))
