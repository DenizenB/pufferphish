import logging
import random
import string
import time
from base64 import b64encode
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


class Flaresolverr:
    def __init__(self):
        self.url = "http://flaresolverr:8080/v1"

    def request(self, command, **data) -> Dict:
        data['cmd'] = command

        r = requests.post(self.url, json=data)
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

    def solve(self, url) -> Dict[str, Any]:
        """
            Solves a captcha on the URL, if found, and returns the solution as arguments for the Chrome browser
        """
        solution = self.get(url).get('solution')

        if solution:
            return {
                'user_agent': solution.get('userAgent'),
                'cookies': [{
                    'name': c['name'],
                    'value': c['value'],
                } for c in solution.get('cookies', [])
                ]
            }

        return {}

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

    sel_username : ClassVar[str] = "input[type='text']:not([disabled]), input[type='email']:not([disabled])"
    sel_password : ClassVar[str] = "input[type='password']:not([disabled])"
    sel_username_or_password : ClassVar[str] = "input[type='text']:not([disabled]), input[type='email']:not([disabled]), input[type='password']:not([disabled])"
    sel_submit : ClassVar[str] = "input[value='Sign in'], input[value='Log in'], input[value='Login'], input[value='Continue'], input[value='Submit']"

    exfiltration : List[Dict[str, Any]]
    html : Optional[str]
    status : Optional[int]

    browser : Optional[uc.Chrome]
    solver : Flaresolverr

    def __init__(self, solver : Flaresolverr):
        self.solver = solver
        self.browser = None

        self.exfiltration = []
        self.html = None
        self.status = None

    def __enter__(self):
        if not VictimSimulator.virtual_display:
            VictimSimulator.virtual_display = Xvfb()
            VictimSimulator.virtual_display.start()

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.browser:
            self.browser.quit()
            self.browser = None

    def visit(self, url : str):
        # Use Flaresolverr in case there's a captcha
        solution = self.solver.solve(url)

        # Start up browser with the user agent from the captcha solution
        self._start(user_agent=solution.get('user_agent'))

        # Generate credentials and set up interception
        username, password = self._generate_credentials()
        self._intercept_exfiltration(username, password)

        # Visit the suspected phishing page
        self.browser.get(url)

        # Should we set any cookies from the captcha solution?
        cookies = solution.get('cookies', [])
        if cookies:
            for cookie in cookies:
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
            options.add_argument(f'--user-agent="{user_agent}"')

        seleniumwire_options = {
            'request_storage': "memory",
            'request_storage_max_size': 200,
            'suppress_connection_errors': False,
            'verify_ssl': False,
        }

        self.browser = uc.Chrome(
            options=options,
            seleniumwire_options=seleniumwire_options,
        )

        self.browser.set_page_load_timeout(5)

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
            * aborts the request(s) that contain the password
            * stores details in self.exfiltration
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

        def interceptor(request : Request, exfiltration : List[Dict[str, Any]] = self.exfiltration, logger = app.logger):
            url = request.url
            logger.debug(f"Intercepted request: {url}")

            url_bytes = url.encode()
            body_bytes = request.body

            exfiltrated_credentials = []
            for credential_type, needles in needles_by_creds.items():
                for needle in needles:
                    if needle in url_bytes or needle in body_bytes:
                        logger.info(f"Found {credential_type} exfiltrated to: {url}")
                        exfiltrated_credentials.append(credential_type)

                        # Sometimes the email address is submitted first in its own request
                        # We don't abort that request since we want to see where the password is sent off to
                        if credential_type == "password":
                            request.abort()

                        # Stop looking for this credential type; it's already been found
                        break

            if exfiltrated_credentials:
                exfiltration.append({
                    'method': request.method,
                    'url': url,
                    'body': body_bytes.decode(),
                    'credential_types': exfiltrated_credentials,
                })

        self.browser.request_interceptor = interceptor

    def _submit_credentials(self, username, password):
        try:
            app.logger.info("Waiting for user or password input field, max 10 sec")
            WebDriverWait(self.browser, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, self.sel_username_or_password))
            )
        except TimeoutException:
            app.logger.info("Timed out waiting for fields")

        # Grab HTML before we start editing fields
        self.html = self.browser.execute_script("return document.documentElement.outerHTML")

        password_inputs = self.browser.find_elements(By.CSS_SELECTOR, self.sel_password)
        can_enter_password = any(
            input.is_displayed() and input.is_enabled()
                for input in password_inputs
        )

        # Enter username, if possible
        username_inputs = self.browser.find_elements(By.CSS_SELECTOR, self.sel_username)
        app.logger.debug(f"Username inputs: {username_inputs}")
        attempts = 3
        for input in username_inputs:
            for attempt in range(1, attempts+1):
                try:
                    app.logger.debug(f"Username input: {input}")

                    app.logger.debug("Clearing field")
                    input.send_keys(Keys.CONTROL + "a")
                    input.send_keys(Keys.DELETE)

                    app.logger.debug("Entering username")
                    input.send_keys(username)

                    if not can_enter_password:
                        app.logger.debug("Pressing enter in user input")
                        input.send_keys(Keys.ENTER)

                        app.logger.debug("Waiting for password field, max 10 sec")
                        WebDriverWait(self.browser, 10).until(
                            EC.presence_of_element_located((By.CSS_SELECTOR, self.sel_password))
                        )

                    break
                except (ElementNotVisibleException, ElementNotInteractableException) as e:
                    if attempt == attempts:
                        app.logger.warning(f"{type(e).__name__}, skipping")
                    else:
                        app.logger.warning(f"{type(e).__name__}, retrying in 5 sec")
                        time.sleep(5)

        password_inputs = self.browser.find_elements(By.CSS_SELECTOR, self.sel_password)
        app.logger.debug(f"Password inputs: {password_inputs}")
        for input in password_inputs:
            for attempt in range(1, attempts+1):
                try:
                    app.logger.debug(f"Using password input: {input}")

                    app.logger.debug("Clearing field")
                    input.send_keys(Keys.CONTROL + "a")
                    input.send_keys(Keys.DELETE)

                    app.logger.debug("Entering password")
                    input.send_keys(password)

                    # Submit form
                    app.logger.debug("Pressing enter in password input")
                    input.send_keys(Keys.ENTER)
                except (ElementNotVisibleException, ElementNotInteractableException) as e:
                    if attempt == attempts:
                        app.logger.warning(f"Password input gone or hidden, skipping")
                    else:
                        app.logger.warning(f"Password input gone or hidden, retrying in 5 sec")
                        time.sleep(5)
                except StaleElementReferenceException:
                    app.logger.warning("Password input has gone stale, skipping")

        try:
            submit_button = self.browser.find_element(By.CSS_SELECTOR, self.sel_submit)
            app.logger.debug("Clicking submit button: {submit_button}")
            submit_button.click()
        except NoSuchElementException:
            pass

        # Wait for exfiltration, max 5 sec
        app.logger.debug("Waiting for 5 seconds to allow exfiltration")
        time.sleep(5)

        app.logger.debug("We're done submitting credentials")

    def get_result(self) -> Dict[str, Any]:
        if self.exfiltration:
            return {
                'exfiltration': self.exfiltration,
            }

        return {
            'error': "No exfiltration observed",
            'html': self.html,
        }

app = Flask(__name__)
captcha_solver = Flaresolverr()

@app.route("/create")
def create():
    return jsonify(captcha_solver.create_session())

@app.route("/list")
def list():
    return jsonify(captcha_solver.get_sessions())

@app.route("/submit", methods=["POST"])
def submit():
    url = request.form['url']

    with VictimSimulator(captcha_solver) as simulator:
        try:
            simulator.visit(url)
        except Exception as e:
            app.logger.exception("Simulation failed")
            response = jsonify({
                'error': str(e),
            })
            response.status_code = 500
            return response

        return jsonify(simulator.get_result())

if __name__ == '__main__':
    app.logger.setLevel(logging.DEBUG)
    app.logger.info("Ready to serve")
    app.run(debug=True, host="0.0.0.0", port=8080, threaded=False, processes=1)
