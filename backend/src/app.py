import logging
import random
import string
import tempfile
import time
from base64 import b64encode
from os import environ as env
from urllib.parse import quote
from sys import stderr
from typing import Dict, List, Optional, Any, ClassVar

import requests
import seleniumwire.undetected_chromedriver as uc
from flask import Flask, request, jsonify, abort
from selenium.common.exceptions import NoSuchElementException, ElementNotVisibleException, TimeoutException, StaleElementReferenceException, ElementNotInteractableException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from seleniumwire.request import Request
from xvfbwrapper import Xvfb

from util import base64_offsets

class FlaresolverrError(Exception):
    pass

class BannedError(Exception):
    pass

class Solution:
    user_agent : Optional[str]
    html : Optional[str]
    cookies : List[Dict[str, str]]

    def __init__(self, user_agent : Optional[str] = None, html : Optional[str] = None, cookies : List[Dict[str, str]] = None):
        self.user_agent = user_agent
        self.html = html
        self.cookies = cookies or []

class Exfiltration:
    method: str
    url: str
    body: str
    credential_types: List[str]

    def __init__(self, method: str, url: str, body: str, credential_types: List[str]):
        self.method = method
        self.url = url
        self.body = body
        self.credential_types = credential_types

    def to_dict(self):
        return {
            'method': self.method,
            'url': self.url,
            'body': self.body,
            'credential_types': self.credential_types,
        }

    def __eq__(self, other):
        if type(other) != Exfiltration:
            return False

        return (
            self.method == other.method
            and self.url == other.url
            and self.body == other.body
            and self.credential_types == other.credential_types
        )

class Result:
    exfiltration : List[Exfiltration]
    html : str
    solver_html : str

    def __init__(self):
        self.exfiltration = []
        self.html = None
        self.solver_html = None

    def to_dict(self):
        return {
            'exfiltration': [exfil.to_dict() for exfil in self.exfiltration],
            'html': self.html,
            'solver_html': self.solver_html,
        }

class Flaresolverr:
    def __init__(self):
        self.url = "http://flaresolverr:8080/v1"

    def request(self, command, **data) -> Dict:
        data['cmd'] = command

        r = requests.post(self.url, json=data, timeout=20)
        resp = r.json()

        if resp.get('status') != "ok":
            app.logger.error("Got non-ok response from flaresolverr: " + r.text)
            raise FlaresolverrError(resp.get('message'))

        r.raise_for_status()
        return resp

    def get_sessions(self) -> List[str]:
        return self.request("sessions.list")

    def create_session(self, name : str = None):
        return self.request("sessions.create")['session']

    def destroy_session(self, name : str):
        return self.request("sessions.destroy", session=name)

    def get(self, url, **data):
        data['url'] = url

        return self.request("request.get", **data)

    def solve(self, url) -> Solution:
        """
            Solves a captcha on the URL, if found, and returns the solution
        """
        solution = self.get(url).get('solution') or {}

        return Solution(
            user_agent=solution.get('userAgent'),
            html=solution.get('response'),
            cookies=[{
                    'name': c['name'],
                    'value': c['value'],
                } for c in solution.get('cookies', [])
            ],
        )

class VictimSimulator:
    """
        A victim simulator that opens a suspected phishing page in
        a headless Chrome browser and submits fake credentials into
        any login form found on the page.

        It then intercepts all requests made by the browser to see
        if and where the credentials were exfiltrated to.

        It uses Flaresolverr to bypass hCaptcha, if it's present.

        Heavily inspired by:
          - https://github.com/nf1s/selenium_phishing_detector
    """

    virtual_display : ClassVar[Xvfb] = None

    wait_time : ClassVar[int] = 15
    retry_wait_time : ClassVar[int] = 5

    sel_bypass_content_protection : ClassVar[tuple[By, str]] = (By.CSS_SELECTOR, "button.cf-btn[data-translate='dismiss_and_enter']")
    sel_username : ClassVar[tuple[By, str]] = (By.CSS_SELECTOR, "input[type='text'], input[type='email']")
    sel_password : ClassVar[tuple[By, str]] = (By.CSS_SELECTOR, "input[type='password']")
    sel_username_or_password : ClassVar[tuple[By, str]] = (By.CSS_SELECTOR, "input[type='text'], input[type='email'], input[type='password']")
    sel_continue : ClassVar[tuple[By, str]] = (By.XPATH, "//button[text()='Next'] | //button[text()='Continue'] | //input[@type='submit' and @value='Next'] | //input[@type='submit' and @value='Continue']")
    sel_submit : ClassVar[tuple[By, str]] = (By.CSS_SELECTOR, "input[value='Sign in'], input[value='Log in'], input[value='Login'], input[value='Continue'], input[value='Submit'], input[value='Next']")

    result : Result
    browser : Optional[uc.Chrome]
    solver : Flaresolverr
    debug : bool

    def __init__(self, solver : Flaresolverr, debug : bool = False):
        self.solver = solver
        self.browser = None

        self.result = Result()
        self.debug = debug

    def __enter__(self):
        if not VictimSimulator.virtual_display:
            VictimSimulator.virtual_display = Xvfb()
            VictimSimulator.virtual_display.start()

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.browser:
            self.browser.quit()
            self.browser = None

    def visit(self, url : Optional[str] = None, html : Optional[bytes] = None):
        if html:
            with tempfile.NamedTemporaryFile("wb", suffix=".html") as temp_file:
                with temp_file.file as f:
                    f.write(html)

                return self._visit("file://" + temp_file.name, solve=False)

        return self._visit(url)

    def _visit(self, url : str, solve : bool = True):
        if solve:
            # Use Flaresolverr in case there's a captcha
            solution = self.solver.solve(url)
        else:
            solution = Solution()

        self.result.solver_html = solution.html

        # Start up browser with the user agent from the captcha solution
        self._start(user_agent=solution.user_agent)

        # Generate credentials and set up interception
        username, password = self._generate_credentials()
        self._intercept_exfiltration(username, password)

        # Visit the suspected phishing page
        self.browser.get(url)

        # Should we set any cookies from the captcha solution?
        if solution.cookies:
            for cookie in solution.cookies:
                self.browser.add_cookie(cookie)

            # Refresh the page after cookies have been set
            self.browser.get(url)

        # Submit the credentials
        self._submit_credentials(username, password)

    def _start(self, user_agent : Optional[str] = None):
        """Starts a Chrome browser with given user-agent"""

        # Startup options taken from FlareSolverr
        options = uc.ChromeOptions()
        options.add_argument('--no-sandbox')
        options.add_argument('--window-size=1920,1080')
        options.add_argument('--disable-setuid-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--no-zygote')
        options.add_argument('--disable-gpu-sandbox')
        options.add_argument('--disable-software-rasterizer')
        options.add_argument('--ignore-certificate-errors')
        options.add_argument('--ignore-ssl-errors')
        options.add_argument('--use-gl=swiftshader')

        # Use a virtual display instead of headless, technique taken from FlareSolverr
        #options.add_argument('--headless')

        if user_agent:
            options.add_argument(f'--user-agent={user_agent}')

        seleniumwire_options = {
            'request_storage': "memory",
            'request_storage_max_size': 200,
            'verify_ssl': False,
            'ignore_http_methods': [], # Capture all methods, including OPTIONS
            'enable_har': self.debug, # Store all requests in request.har
            'suppress_connection_errors': False,
        }

        proxy = env.get('PROXY')
        if proxy:
            app.logger.info(f"Using proxy {proxy}")
            seleniumwire_options['proxy'] = {
                'http': proxy,
                'https': proxy,
            }

        self.browser = uc.Chrome(
            options=options,
            seleniumwire_options=seleniumwire_options,
        )

        self.browser.set_page_load_timeout(15)

    def _generate_credentials(self) -> (str, str):
        """Generates random credentials as a tuple of (username, password)"""
        usernames = [
            "bartholomew.bumblebrook",
            "florence.fluffernut",
            "percival.puddlejump",
            "beatrice.bumblebuns",
            "neville.noodleknock",
            "prudence.poppleshorts",
            "archibald.appleboggle",
            "matilda.muddlefoot",
            "reginald.rumblepot",
            "agnes.amblequack",
        ]
        domains = [
            "ball.com",
            "pplweb.com",
            "stryker.com",
            "appliedmaterials.com",
            "arconic.com",
            "jacobs.com",
            "dteenergy.com",
            "l3t.com",
            "synchronyfinancial.com",
            "parker.com",
        ]

        username = random.choice(usernames) + "@" + random.choice(domains)
        password = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))

        return (username, password)

    def _intercept_exfiltration(self, username : str, password : str):
        """This method:
            * intercepts any request that contains the given credentials
            * aborts the request(s) that contain creds
            * stores details in self.result.exfiltration
        """
        needles_by_creds = {
            'username': set([
                username.encode(),
                quote(username).encode(),
            ] + [
                offset.encode()
                    for offset in base64_offsets(username)
            ]),
            'password': set([
                password.encode(),
                quote(password).encode()
            ] + [
                offset.encode()
                    for offset in base64_offsets(password)
            ]),
        }

        def interceptor(request : Request, exfiltration : List[Exfiltration] = self.result.exfiltration, logger = app.logger):
            url = request.url
            method = request.method
            logger.info(f"*** {method} {url}")

            url_bytes: bytes = url.encode()
            body: bytes = request.body
            headers: List[tuple[bytes, bytes]] = [(k.encode(), v.encode()) for k, v in request.headers.items()]
            websocket_messages: List[bytes] = [m.content if type(m.content) == bytes else m.content.encode() for m in request.ws_messages]

            exfiltrated_credentials = []
            for credential_type, needles in needles_by_creds.items():
                for needle in needles:
                    is_exfiltration = (
                        needle in url_bytes
                        or needle in body
                        or any(needle in k or needle in v for k, v in headers)
                        or any(needle in message for message in websocket_messages)
                    )

                    if is_exfiltration:
                        request.abort()

                        logger.info(f"Blocked {credential_type} exfiltration to: {url}")
                        exfiltrated_credentials.append(credential_type)

                        # Replace creds with placeholders
                        url_bytes = url_bytes.replace(needle, credential_type.upper().encode())
                        body = body.replace(needle, credential_type.upper().encode())

                        # Stop looking for this credential type; it's already been found
                        break

            if exfiltrated_credentials:
                exfil = Exfiltration(
                    request.method,
                    url_bytes.decode(errors="ignore"),
                    body.decode(errors="ignore"),
                    exfiltrated_credentials,
                )

                if not exfil in exfiltration:
                    exfiltration.append(exfil)

        self.browser.request_interceptor = interceptor

    def _submit_credentials(self, username, password):
        try:
            bypass_protection_btn = self.browser.find_element(*self.sel_bypass_content_protection)
            app.logger.debug("Bypassing content protection screen")
            bypass_protection_btn.click()
        except (NoSuchElementException, ElementNotVisibleException, ElementNotInteractableException):
            pass

        try:
            app.logger.info(f"Waiting for user or password input field, max {self.wait_time} sec")
            WebDriverWait(self.browser, self.wait_time).until(
                EC.presence_of_element_located(self.sel_username_or_password)
            )
        except TimeoutException:
            app.logger.debug("Timed out waiting for inputs")

        # Grab HTML before we start editing fields
        html = self.result.html = self.browser.execute_script("return document.documentElement.outerHTML")

        password_inputs = self.browser.find_elements(*self.sel_password)
        can_enter_password = any(
            input.is_displayed() and input.is_enabled()
                for input in password_inputs
        )

        # Enter username, if possible
        app.logger.info(f"Attempting to input username: {username}")
        attempts = 3
        for attempt in range(1, attempts+1):
            try:
                input = self.browser.find_element(*self.sel_username)
                app.logger.debug(f"Username input: {input}")

                app.logger.debug("Clearing field")
                input.send_keys(Keys.CONTROL + "a")
                input.send_keys(Keys.DELETE)

                app.logger.debug("Entering username")
                input.send_keys(username)

                if not can_enter_password:
                    app.logger.debug("Pressing enter in user input")
                    input.send_keys(Keys.ENTER)

                    time.sleep(1)
                    try:
                        continue_button = self.browser.find_element(*self.sel_continue)
                        app.logger.debug(f"Clicking continue button: {continue_button}")
                        continue_button.click()
                    except (NoSuchElementException, ElementNotVisibleException, ElementNotInteractableException):
                        pass

                try:
                    app.logger.debug(f"Waiting for password field, max {self.wait_time} sec")
                    WebDriverWait(self.browser, self.wait_time).until(
                        EC.presence_of_element_located(self.sel_password)
                    )
                except TimeoutException:
                    app.logger.debug("Timed out waiting for password field")

                break
            except (NoSuchElementException, ElementNotVisibleException, ElementNotInteractableException) as e:
                if attempt == attempts:
                    app.logger.info(f"Failed to input username: {type(e).__name__}")
                else:
                    app.logger.debug(f"{type(e).__name__}, retrying in {self.retry_wait_time} sec")
                    time.sleep(self.retry_wait_time)
            except StaleElementReferenceException:
                app.logger.info("User input has gone stale, skipping")
                break

        # Have we already spotted exfiltration?
        if self.result.exfiltration:
            return

        app.logger.info(f"Attempting to input password: {password}")
        for attempt in range(1, attempts+1):
            try:
                input = self.browser.find_element(*self.sel_password)
                app.logger.debug(f"Using password input: {input}")

                app.logger.debug("Clearing field")
                input.send_keys(Keys.CONTROL + "a")
                input.send_keys(Keys.DELETE)

                app.logger.debug("Entering password")
                input.send_keys(password)

                # Submit form
                app.logger.debug("Pressing enter in password input")
                input.send_keys(Keys.ENTER)

                break
            except (NoSuchElementException, ElementNotVisibleException, ElementNotInteractableException) as e:
                if attempt == attempts:
                    app.logger.info(f"Failed to input password: {type(e).__name__}")
                else:
                    app.logger.debug(f"{type(e).__name__}, retrying in {self.retry_wait_time} sec")
                    time.sleep(self.retry_wait_time)
            except StaleElementReferenceException:
                app.logger.info("Password input has gone stale, skipping")
                break

        try:
            submit_button = self.browser.find_element(*self.sel_submit)
            app.logger.debug("Clicking submit button: {submit_button}")
            submit_button.click()
        except (NoSuchElementException, ElementNotVisibleException, ElementNotInteractableException):
            pass

        # Have we already spotted exfiltration?
        if self.result.exfiltration:
            return

        # Wait for exfiltration, max 5 sec
        app.logger.debug("Waiting for 5 seconds to allow exfiltration")
        time.sleep(5)


app = Flask(__name__)
captcha_solver = Flaresolverr()

@app.route("/submit", methods=["POST"])
def submit():
    visit_args = {}

    url = request.form.get('url')
    uploaded_file = request.files.get('html')
    debug = request.form.get('debug', "").lower() == "true"

    if uploaded_file:
        visit_args['html'] = uploaded_file.read()
    elif url:
        visit_args['url'] = url
    else:
        return "Bad args", 400

    result = {}
    status = 200

    with VictimSimulator(captcha_solver, debug) as simulator:
        try:
            simulator.visit(**visit_args)
        except BannedError as e:
            app.logger.warning(str(e))
            result['error'] = str(e)
            status = 403
        except Exception as e:
            app.logger.exception("Simulation failed")
            result['error'] = str(e)
            status = 500

        result.update(simulator.result.to_dict())
        if debug:
            result['har'] = simulator.browser.har

        response = jsonify(result)
        response.status_code = status
        return response


if __name__ == '__main__':
    app.logger.setLevel(logging.INFO)
    app.logger.info("Starting app")
    app.run(debug=True, host="0.0.0.0", port=8080, threaded=False, processes=1)
