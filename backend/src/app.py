import random
from base64 import b64encode
from sys import stderr
from typing import Dict, List, Optional, Any, ClassVar

import requests
import seleniumwire.undetected_chromedriver as chrome
from flask import Flask, request, jsonify
from selenium.common.exceptions import NoSuchElementException, ElementNotVisibleException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.ui import WebDriverWait
from seleniumwire.request import Request

from util import base64_offsets


class Flaresolverr:
    def __init__(self):
        self.url = "http://flaresolverr:8080/v1"
        self.session = None

    def request(self, command, **data) -> Dict:
        data['cmd'] = command

        r = requests.post(self.url, json=data)
        r.raise_for_status()

        return r.json()

    def get_sessions(self) -> List[str]:
        return self.request("sessions.list")

    def create_session(self, name : str = None):
        return self.request("sessions.create")['session']

    def destroy_session(self, name : str):
        return self.request("sessions.destroy", session=name)

    def get(self, url, **data):
        if not self.session:
            self.session = self.create_session()

        data['url'] = url
        data['session'] = self.session

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
                    c['name']: c['value']
                        for c in solution.get('cookies', [])
                }]
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

    xpath_username : ClassVar[str] = "//input[(@type='text' or @type='email') and not(@disabled)]"
    xpath_password : ClassVar[str] = "//input[@type='password']"

    exfiltration : List[Dict[str, Any]]
    browser : Optional[chrome.Chrome]
    solver : Flaresolverr

    def __init__(self, solver : Flaresolverr):
        self.solver = solver

        self.exfiltration = []
        self.browser = None

    def visit(self, url : str):
        # Use Flaresolverr in case there's a captcha
        solution = self.solver.solve(url)

        # Start up browser with the captcha solution
        self._start(**solution)

        # Visit the suspected phishing page
        self.browser.get(url)

        # Generate credentials and set up interception
        username, password = self._generate_credentials()
        self._intercept_exfiltration(username, password)

        # Enter the credentials
        self._submit_credentials(username, password)

        # Close browser and return


    def _submit_credentials(self, username, password):
        password_inputs = self.browser.find_elements(By.XPATH, self.xpath_password)
        can_enter_password = any(
            input.is_displayed() and input.is_enabled()
                for input in password_inputs
        )

        # Enter username, if possible
        username_inputs = self.browser.find_elements(By.XPATH, self.xpath_username)
        for input in username_inputs:
            try:
                print(f"Username input: {input}")

                print("Clearing field")
                input.send_keys(Keys.CONTROL + "a")
                input.send_keys(Keys.DELETE)

                print("Entering username")
                input.send_keys(username)

                if not can_enter_password:
                    print("Waiting 2 seconds")
                    WebDriverWait(self.browser, 2)

                    print("Pressing enter in user input")
                    input.send_keys(Keys.ENTER)

                    print("Waiting 2 seconds")
                    WebDriverWait(self.browser, 2)
            except ElementNotVisibleException:
                print(f"Potential user input not visible, skipping: {input}", file=stderr)

        # Click continue if there's no visible password input

        password_inputs = self.browser.find_elements(By.XPATH, self.xpath_password)
        for input in password_inputs:
            try:
                print("Using password input: {input}")

                print("Clearing field")
                input.send_keys(Keys.CONTROL + "a")
                input.send_keys(Keys.DELETE)

                print("Entering password")
                input.send_keys(password)

                # Wait for 2 seconds
                print("Waiting 2 seconds")
                WebDriverWait(self.browser, 2)

                # Submit form
                print("Pressing enter in password input")
                input.send_keys(Keys.ENTER)

                # Wait until the password input is no longer part of the DOM, timout after 5 sec
                print("Waiting until redirected, timeout after 5 seconds")
                WebDriverWait(self.browser, 5).until(expected_conditions.staleness_of(input))
            except ElementNotVisibleException:
                print(f"Potential password input not visible, skipping: {input}", file=stderr)

    def _start(self, user_agent : Optional[str] = None, cookies : Optional[Dict[str, str]] = None):
        """Starts a Chrome browser with given user-agent and cookies"""
        chrome_options = chrome.ChromeOptions()

        if user_agent:
            chrome_options.add_argument(f"user-agent={user_agent}")

        seleniumwire_options = {
            'request_storage': "memory",
            'request_storage_max_size': 200,
        }

        self.browser = chrome.Chrome(
            headless=True,
            options=chrome_options,
            seleniumwire_options=seleniumwire_options,
        )

        if cookies:
            self.browser.add_cookie(cookies)

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
        password = random.choices(string.ascii_lowercase + string.digits, k=10)

        return (username, password)

    def _intercept_exfiltration(self, username : str, password : str):
        """This method:
            * intercepts any request that contains the given credentials
            * aborts the request(s) that contain the password
            * stores details in self.exfiltration
        """
        needles = {
            'username': [
                username.encode(),
            ] + [
                offset.encode()
                    for offset in base64_offsets(username)
            ],
            'password': [
                password.encode(),
            ] + [
                offset.encode()
                    for offset in base64_offsets(password)
            ],
        }

        def interceptor(request : Request, results : List[Dict[str, Any]] = self.exfiltration):
            url = request.url
            url_bytes = url.encode()
            body : bytes = request.body

            for credential_type, needles in needles.items():
                for needle in needles:
                    if needle in url_bytes or needle in body:
                        print(f"Found credential '{credential_type}' exfiltrated as '{needle}' in request to {url}", file=stderr)
                        results.append({
                            'type': credential_type,
                            'url': url,
                            'body': body.decode(),
                        })

                        # Sometimes the email address is submitted first in its own request
                        # We don't abort that request since we want to see where the password is sent off to
                        if credential_type == "password":
                            request.abort()
                            return

        self.browser.request_interceptor = interceptor

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

    simulator = VictimSimulator(captcha_solver)
    simulator.visit(url)

    return jsonify(simulator.exfiltration)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8080)
