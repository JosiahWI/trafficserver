#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  'License'); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an 'AS IS' BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import functools
import re
from typing import Any, Callable, Dict, Optional

from ports import get_port

Test.Summary = 'Tests the escalate plugin.'

TestParams = Dict[str, Any]


class TestEscalate:
    '''Configure a test for escalate.'''

    replay_filepath: str = 'escalate.replay.yaml'
    client_counter: int = 0
    server_counter: int = 0
    ts_counter: int = 0

    def __init__(self, name: str, /, autorun: bool) -> None:
        '''Initialize the test.

        :param name: The name of the test.
        '''
        self.name = name
        self.autorun = autorun

    def _init_run(self) -> 'TestRun':
        '''Initialize processes for the test run.'''

        tr = Test.AddTestRun(self.name)
        server_one = TestEscalate.configure_server(tr, 'yay.com')
        self._configure_traffic_server(tr, server_one)

        tr.Processes.Default.StartBefore(self._ts)

        return {
            'tr': tr,
            'ts': self._ts,
            'server_one': server_one,
            'port_one': self._port_one,
        }

    @classmethod
    def runner(cls, name: str, autorun: bool = True, **kwargs) -> Optional[Callable]:
        '''Create a runner for a test case.

        :param autorun: Run the test case once it's set up. Default is True.
        :return: Returns a runner that can be used as a decorator.
        '''
        test = cls(name, autorun=autorun, **kwargs)._prepare_test_case
        return test

    def _prepare_test_case(self, func: Callable) -> Callable:
        '''Set up a test case and possibly run it.

        :param func: The test case to set up.
        :return: Returns a wrapped function that will have its test params
        passed to it on invocation.
        '''
        functools.wraps(func)
        test_params = self._init_run()

        def wrapper(*args, **kwargs) -> Any:
            return func(test_params, *args, **kwargs)

        if self.autorun:
            wrapper()
        return wrapper

    @staticmethod
    def configure_server(tr: 'TestRun', domain: str):
        server = tr.AddVerifierServerProcess(
            f'server{TestEscalate.server_counter + 1}.{domain}', TestEscalate.replay_filepath, other_args='--format \'{url}\'')
        TestEscalate.server_counter += 1

        return server

    def _configure_traffic_server(self, tr: 'TestRun', server_one: 'Process'):
        '''Configure Traffic Server.

        :param tr: The TestRun object to associate the ts process with.
        '''
        ts = tr.MakeATSProcess(f'ts-{TestEscalate.ts_counter + 1}', enable_tls=True, enable_cache=True)
        TestEscalate.ts_counter += 1

        ts.addDefaultSSLFiles()
        self._port_one = get_port(ts, 'PortOne')
        ts.Disk.records_config.update(
            {
                'proxy.config.ssl.server.cert.path': f'{ts.Variables.SSLDir}',
                'proxy.config.ssl.server.private_key.path': f'{ts.Variables.SSLDir}',
                'proxy.config.http.server_ports': f'{self._port_one}:ssl',
                'proxy.config.http.redirect.actions': 'self:follow',
                'proxy.config.http.number_of_redirections': 0,
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.debug.tags': 'escalate|http',
            })

        server_target = f'http://localhost:{server_one.Variables.http_port}'
        ts.Disk.remap_config.AddLine(f'map / {server_target} \\')
        ts.Disk.remap_config.AddLine(f'  @plugin=escalate.so @pparam=400:{server_target}/other_resource')

        ts.Disk.ssl_multicert_config.AddLine(f'dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

        self._ts = ts


# Tests start.


@TestEscalate.runner('See what breaks with escalate!')
def test1(params: TestParams) -> None:
    client = params['tr'].Processes.Default
    client.Command = 'curl -k -v "https://localhost:{0}/resource"; curl -k -v "https://localhost:{0}/resource"'.format(
        params['port_one'])

    client.ReturnCode = 0
    client.Streams.stdout += Testers.ContainsExpression(r'Yay!', 'We should receive the expected body.')
