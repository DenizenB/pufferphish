import asyncio
from theading import Thread
from typing import List

import mitmproxy
import mitmproxy.http
import mitmproxy.master
import mitmproxy.options
import mitmproxy.tools.dump


class CredentialInterceptor:
    needles : Dict[str, List[str]]
    exfiltration_urls : List[tuple[str, str]]

    def __init__(self, username, password):
        self.needles = {
            'password': [
                password,
            ] + base64_offsets(password),
            'username': [
                username,
            ] + base64_offsets(username),
        }

        self.exfiltration_urls = []

    def request(self, flow: mitmproxy.http.HTTPFlow):
        if flow.request.method == 'POST':
            request_body = flow.request.get_text()

            for credential_type, needles in self.needles.items():
                for needle in needles:
                    if needle in request_body:
                        print(f"Found credential '{credential_type}' exfiltrated as '{needle}' in request to {flow.request.url}", file=stderr)
                        self.exfiltration.urls.append((credential_type, flow.request.url))
                        flow.kill()
                        return

class MitmproxyHelper(Thread):
    def __init__(self, port : int = 3128):
        super().__init__()

        self.port = port
        self.event_loop = asyncio.new_event_loop()

    def run(self):
        options = mitmproxy.options.Options(listen_host="0.0.0.0", listen_port=self.port)
        #self.master = mitmproxy.master.Master(self.options, event_loop=self.event_loop)
        self.master = mitmproxy.tools.dump.DumpMaster(options, loop=self.event_loop, with_termlog=True, with_dumper=False)

        self.event_loop.create_task(self.master.run())
        self.event_loop.run_forever()

    def intercept(self, username, password) -> CredentialInterceptor:
        addon = CredentialInterceptor(username, password)

        def add():
            self.master.addons.add(addon)

        self.event_loop.call_soon_threadsafe(add)
        return addon
