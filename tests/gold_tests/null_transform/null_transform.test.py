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

Test.Summary = '''
Test a basic null transform plugin
'''

Test.SkipUnless(Condition.PluginExists('null_transform.so'))

Test.ContinueOnFail = True

# Define default ATS
ts = Test.MakeATSProcess("ts")
server = Test.MakeOriginServer("server")

Test.testName = ""
request_header = {"headers": "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
# Expected response from origin server
response_header = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "This is expected response."
}

# Add response the server dictionary
server.addResponse("sessionfile.log", request_header, response_header)
ts.Disk.records_config.update(
    {
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.show_location': 0,
        'proxy.config.diags.debug.tags': 'null_transform'
    })
ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(server.Variables.Port))

# Load plugin
Test.PrepareInstalledPlugin('null_transform.so', ts)

# www.example.com Host
tr = Test.AddTestRun()
tr.MakeCurlCommand(
    '--proxy 127.0.0.1:{0} "http://www.example.com" --verbose -H "Proxy-Connection: keep-alive"'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(Test.Processes.ts)
tr.Processes.Default.Streams.stderr = "gold/null_transform-200.gold"
tr.StillRunningAfter = server

# Check Plugin Loading Information
ts.Disk.traffic_out.Content = "gold/null_transform-tag.gold"
