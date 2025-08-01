'''
'''
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os

Test.Summary = '''
Test custom log file format
'''

# this test depends on Linux specific behavior regarding loopback addresses
Test.SkipUnless(Condition.IsPlatform("linux"), Condition.CurlUsingUnixDomainSocket())

# Define default ATS
ts = Test.MakeATSProcess("ts", enable_proxy_protocol=True)

# setup some config file for this server
ts.Disk.remap_config.AddLine('map / http://www.linkedin.com/ @action=deny')

ts.Disk.logging_yaml.AddLines(
    '''
logging:
  formats:
    - name: custom
      format: "%<pps>"
  logs:
    - filename: test_log_field
      format: custom
'''.split("\n"))

# #########################################################################
# at the end of the different test run a custom log file should exist
# Because of this we expect the testruns to pass the real test is if the
# customlog file exists and passes the format check
Test.Disk.File(os.path.join(ts.Variables.LOGDIR, 'test_log_field.log'), exists=True, content='gold/custom_uds.gold')

# first test is a miss for default
tr = Test.AddTestRun()
tr.MakeCurlCommand(
    '"http://127.0.0.1:{0}" --verbose --haproxy-protocol 1 --haproxy-clientip 127.0.0.1'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(Test.Processes.ts)

tr = Test.AddTestRun()
tr.MakeCurlCommand(
    '"http://127.1.1.1:{0}" --verbose --haproxy-protocol 1 --haproxy-clientip 127.1.1.1'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun()
tr.MakeCurlCommand(
    '"http://127.2.2.2:{0}" --verbose --haproxy-protocol 1 --haproxy-clientip 127.2.2.2'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun()
tr.MakeCurlCommand(
    '"http://127.3.3.3:{0}" --verbose --haproxy-protocol 1 --haproxy-clientip 127.3.3.3'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun()
tr.MakeCurlCommand(
    '"http://127.3.0.1:{0}" --verbose --haproxy-protocol 1 --haproxy-clientip 127.3.0.1'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun()
tr.MakeCurlCommand(
    '"http://127.43.2.1:{0}" --verbose --haproxy-protocol 1 --haproxy-clientip 127.43.2.1'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun()
tr.MakeCurlCommand(
    '"http://127.213.213.132:{0}" --verbose --haproxy-protocol 1 --haproxy-clientip 127.213.213.132'.format(ts.Variables.port),
    ts=ts)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun()
tr.MakeCurlCommand(
    '"http://127.123.32.243:{0}" --verbose --haproxy-protocol 1 --haproxy-clientip 127.123.32.243'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.ReturnCode = 0

# Wait for log file to appear, then wait one extra second to make sure TS is done writing it.
test_run = Test.AddTestRun()
test_run.Processes.Default.Command = (
    os.path.join(Test.Variables.AtsTestToolsDir, 'condwait') + ' 60 1 -f ' +
    os.path.join(ts.Variables.LOGDIR, 'test_log_field.log'))
test_run.Processes.Default.ReturnCode = 0
