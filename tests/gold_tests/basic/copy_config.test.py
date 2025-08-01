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

Test.Summary = "Test start up of Traffic server with configuration modification of starting port of different servers at the same time"

# set up some ATS processes
ts1 = Test.MakeATSProcess("ts1", select_ports=False)
ts1.Variables.port = 8090
ts1.Disk.records_config.update({
    'proxy.config.http.server_ports': str(ts1.Variables.port) + f" {ts1.Variables.uds_path}",
})
ts1.Ready = When.PortOpen(ts1.Variables.port)

ts2 = Test.MakeATSProcess("ts2", select_ports=False, enable_uds=False)
ts2.Variables.port = 8091
ts2.Disk.records_config.update({
    'proxy.config.http.server_ports': str(ts2.Variables.port),
})
ts2.Ready = When.PortOpen(ts2.Variables.port)

# setup a testrun
t = Test.AddTestRun("Talk to ts1")
t.Processes.Default.StartBefore(ts1)
t.Processes.Default.StartBefore(ts2)
t.MakeCurlCommand("127.0.0.1:{port}".format(port=ts1.Variables.port), ts=ts1)
t.ReturnCode = 0
t.StillRunningAfter = ts1
t.StillRunningAfter += ts2

# setup a testrun
t = Test.AddTestRun("Talk to ts2")
t.MakeCurlCommandMulti("{{curl_base}} 127.0.0.1:{port}".format(port=ts2.Variables.port), ts=ts2)
t.ReturnCode = 0
t.StillRunningAfter = ts1
t.StillRunningAfter += ts2
