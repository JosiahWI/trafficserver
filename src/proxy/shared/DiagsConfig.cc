/** @file

  A brief file description

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include "tscore/ink_platform.h"
#include "tscore/ink_memory.h"
#include "tscore/ink_file.h"
#include "tscore/Layout.h"
#include "tscore/Filenames.h"
#include "proxy/shared/DiagsConfig.h"
#include "../../records/P_RecCore.h"

//////////////////////////////////////////////////////////////////////////////
//
//      void reconfigure_diags()
//
//      This function extracts the current diags configuration settings from
//      records.yaml, and rebuilds the Diags data structures.
//
//////////////////////////////////////////////////////////////////////////////

void
DiagsConfig::reconfigure_diags()
{
  int              i;
  DiagsConfigState c;
  bool             found, all_found;

  static struct {
    const char *config_name;
    DiagsLevel  level;
  } output_records[] = {
    {"proxy.config.diags.output.diag",      DL_Diag     },
    {"proxy.config.diags.output.debug",     DL_Debug    },
    {"proxy.config.diags.output.status",    DL_Status   },
    {"proxy.config.diags.output.note",      DL_Note     },
    {"proxy.config.diags.output.warning",   DL_Warning  },
    {"proxy.config.diags.output.error",     DL_Error    },
    {"proxy.config.diags.output.fatal",     DL_Fatal    },
    {"proxy.config.diags.output.alert",     DL_Alert    },
    {"proxy.config.diags.output.emergency", DL_Emergency},
    {nullptr,                               DL_Undefined},
  };

  if (!callbacks_established) {
    register_diags_callbacks();
  }
  ////////////////////////////////////////////
  // extract relevant records.yaml values //
  ////////////////////////////////////////////

  all_found = true;

  // initial value set to 0 or 1 based on command line tags
  c.enabled(DiagsTagType_Debug, _diags->base_debug_tags != nullptr ? 1 : 0);
  c.enabled(DiagsTagType_Action, _diags->base_action_tags != nullptr ? 1 : 0);

  // enabled if records.yaml set

  auto e{RecGetRecordInt("proxy.config.diags.debug.enabled")};
  found = e.has_value();
  if (found && e.value()) {
    c.enabled(DiagsTagType_Debug, e.value()); // implement OR logic
  }
  all_found = all_found && found;

  e     = RecGetRecordInt("proxy.config.diags.action.enabled");
  found = e.has_value();
  if (found && e.value()) {
    c.enabled(DiagsTagType_Action, 1); // implement OR logic
  }
  all_found = all_found && found;

  e     = RecGetRecordInt("proxy.config.diags.show_location");
  found = e.has_value();
  _diags->show_location =
    ((found && e.value() == 1) ? SHOW_LOCATION_DEBUG : ((found && e.value() == 2) ? SHOW_LOCATION_ALL : SHOW_LOCATION_NONE));
  all_found = all_found && found;

  // read output routing values
  for (i = 0;; i++) {
    const char *record_name = output_records[i].config_name;
    DiagsLevel  l           = output_records[i].level;

    if (!record_name) {
      break;
    }

    auto rec_str{RecGetRecordStringAlloc(record_name)};
    found     = rec_str.has_value();
    all_found = all_found && found;

    if (found) {
      parse_output_string(ats_as_c_str(rec_str), &(c.outputs[l]));
    } else {
      Error("can't find config variable '%s'", record_name);
    }
  }

  auto dt{RecGetRecordStringAlloc("proxy.config.diags.debug.tags")};
  found     = dt.has_value();
  all_found = all_found && found;

  auto at{RecGetRecordStringAlloc("proxy.config.diags.action.tags")};
  found     = at.has_value();
  all_found = all_found && found;

  ///////////////////////////////////////////////////////////////////
  // if couldn't read all values, return without changing config,  //
  // otherwise rebuild taglists and change the diags config values //
  ///////////////////////////////////////////////////////////////////

  if (!all_found) {
    Error("couldn't fetch all proxy.config.diags values");
  } else {
    //////////////////////////////
    // clear out old tag tables //
    //////////////////////////////

    _diags->deactivate_all(DiagsTagType_Debug);
    _diags->deactivate_all(DiagsTagType_Action);

    //////////////////////////////////////////////////////////////////////
    // add new tag tables from records.yaml or command line overrides //
    //////////////////////////////////////////////////////////////////////

    _diags->activate_taglist((_diags->base_debug_tags ? _diags->base_debug_tags : ats_as_c_str(dt)), DiagsTagType_Debug);
    _diags->activate_taglist((_diags->base_action_tags ? _diags->base_action_tags : ats_as_c_str(at)), DiagsTagType_Action);

    ////////////////////////////////////
    // change the diags config values //
    ////////////////////////////////////
    _diags->config = c;
    Note("updated diags config");
  }
}

//////////////////////////////////////////////////////////////////////////////
//
//      static void *diags_config_callback(void *opaque_token, void *data)
//
//      This is the records.yaml registration callback that is called
//      when any diags value is changed.  Each time a diags value changes
//      the entire diags state is reconfigured.
//
//////////////////////////////////////////////////////////////////////////////
static int
diags_config_callback(const char * /* name ATS_UNUSED */, RecDataT /* data_type ATS_UNUSED */, RecData /* data ATS_UNUSED */,
                      void *opaque_token)
{
  DiagsConfig *diagsConfig;

  diagsConfig = static_cast<DiagsConfig *>(opaque_token);
  ink_assert(::diags()->magic == DIAGS_MAGIC);
  diagsConfig->reconfigure_diags();
  return (0);
}

//////////////////////////////////////////////////////////////////////////////
//
//      void Diags::parse_output_string(char *s, DiagsModeOutput *o)
//
//      This routine converts a diags outpur routing string <s> to the
//      internal DiagsModeOutput structure.  Currently there are 4 possible
//      routing destinations:
//              O  stdout
//              E  stderr
//              S  syslog
//              L  diags.log
//
//////////////////////////////////////////////////////////////////////////////

void
DiagsConfig::parse_output_string(const char *s, DiagsModeOutput *o)
{
  o->to_stdout   = (s && strchr(s, 'O'));
  o->to_stderr   = (s && strchr(s, 'E'));
  o->to_syslog   = (s && strchr(s, 'S'));
  o->to_diagslog = (s && strchr(s, 'L'));
}

//////////////////////////////////////////////////////////////////////////////
//
//      void Diags::config_norecords()
//
//      Builds the Diags data structures based on the command line values
//        it does not use any of the records based config variables
//
//////////////////////////////////////////////////////////////////////////////
void
DiagsConfig::config_diags_norecords()
{
  DiagsConfigState c;
  ink_zero(c);

  //////////////////////////////
  // clear out old tag tables //
  //////////////////////////////
  _diags->deactivate_all(DiagsTagType_Debug);
  _diags->deactivate_all(DiagsTagType_Action);

  //////////////////////////////////////////////////////////////////////
  // add new tag tables from command line overrides only              //
  //////////////////////////////////////////////////////////////////////

  if (_diags->base_debug_tags) {
    _diags->activate_taglist(_diags->base_debug_tags, DiagsTagType_Debug);
    c.enabled(DiagsTagType_Debug, 1);
  } else {
    c.enabled(DiagsTagType_Debug, 0);
  }

  if (_diags->base_action_tags) {
    _diags->activate_taglist(_diags->base_action_tags, DiagsTagType_Action);
    c.enabled(DiagsTagType_Action, 1);
  } else {
    c.enabled(DiagsTagType_Action, 0);
  }

  // Route all outputs to stderr by default until reconfigured with records.yaml
  for (auto &o : c.outputs) {
    o.to_stderr = true;
  }

#if !defined(__GNUC__)
  _diags->config = c;
#else
  memcpy(((void *)&_diags->config), ((void *)&c), sizeof(DiagsConfigState));
#endif
}

DiagsConfig::DiagsConfig(std::string_view prefix_string, const char *filename, const char *tags, const char *actions,
                         bool use_records)
  : callbacks_established(false), diags_log(nullptr), _diags(nullptr)
{
  ats_scoped_str logpath;

  ////////////////////////////////////////////////////////////////////
  //  If we aren't using the manager records for configuration      //
  //   just build the tables based on command line parameters and   //
  //   exit                                                         //
  ////////////////////////////////////////////////////////////////////

  if (!use_records) {
    _diags = std::make_unique<Diags>(prefix_string, tags, actions, nullptr);
    DiagsPtr::set(_diags.get());
    config_diags_norecords();
    return;
  }

  // Open the diagnostics log. If proxy.config.log.logfile_dir is set use that, otherwise fall
  // back to the configured log directory.

  logpath = RecConfigReadLogDir();
  if (access(logpath, W_OK | R_OK) == -1) {
    fprintf(stderr, "unable to access log directory '%s': %d, %s\n", (const char *)logpath, errno, strerror(errno));
    fprintf(stderr, "please set 'proxy.config.log.logfile_dir'\n");
    ::exit(1);
  }

  std::string diags_logpath{filename};
  // "stdout" and "stderr" are treated specially by BaseLogFile and are used to
  // write to the stdout and stderr streams, respectively. If the caller
  // specified these, we don't prepend any path and simply pass those strings
  // as such to BaseLogFile.
  if (diags_logpath != "stdout" && diags_logpath != "stderr") {
    char buf[PATH_NAME_MAX];
    ink_filepath_make(buf, sizeof(buf), logpath, filename);
    diags_logpath = std::string(buf);
  }

  // Grab rolling intervals from configuration
  // TODO error check these values
  int output_log_roll_int;
  output_log_roll_int = RecGetRecordInt("proxy.config.output.logfile.rolling_interval_sec").value_or(0);
  int output_log_roll_size;
  output_log_roll_size = RecGetRecordInt("proxy.config.output.logfile.rolling_size_mb").value_or(0);
  int output_log_roll_enable;
  output_log_roll_enable = RecGetRecordInt("proxy.config.output.logfile.rolling_enabled").value_or(0);
  int diags_log_roll_int;
  diags_log_roll_int = RecGetRecordInt("proxy.config.diags.logfile.rolling_interval_sec").value_or(0);
  int diags_log_roll_size;
  diags_log_roll_size = RecGetRecordInt("proxy.config.diags.logfile.rolling_size_mb").value_or(0);
  int diags_log_roll_enable;
  diags_log_roll_enable = RecGetRecordInt("proxy.config.diags.logfile.rolling_enabled").value_or(0);

  // Grab some perms for the actual files on disk
  {
    auto diags_perm{RecGetRecordStringAlloc("proxy.config.diags.logfile_perm")};
    auto output_perm{RecGetRecordStringAlloc("proxy.config.output.logfile_perm")};
    auto diags_perm_c_str{ats_as_c_str(diags_perm)};
    auto output_perm_c_str{ats_as_c_str(output_perm)};
    int  diags_perm_parsed  = diags_perm_c_str ? ink_fileperm_parse(diags_perm_c_str) : -1;
    int  output_perm_parsed = output_perm_c_str ? ink_fileperm_parse(output_perm_c_str) : -1;

    // Set up diags, FILE streams are opened in Diags constructor
    diags_log = new BaseLogFile(diags_logpath.c_str());
    _diags    = std::make_unique<Diags>(prefix_string, tags, actions, diags_log, diags_perm_parsed, output_perm_parsed);
  }
  DiagsPtr::set(_diags.get());
  _diags->config_roll_diagslog(static_cast<RollingEnabledValues>(diags_log_roll_enable), diags_log_roll_int, diags_log_roll_size);
  _diags->config_roll_outputlog(static_cast<RollingEnabledValues>(output_log_roll_enable), output_log_roll_int,
                                output_log_roll_size);

  Status("opened %s", diags_logpath.c_str());

  register_diags_callbacks();

  reconfigure_diags();
}

//////////////////////////////////////////////////////////////////////////////
//
//      void DiagsConfig::register_diags_callbacks()
//
//      set up management callbacks to update diags on every change ---   //
//      right now, this system kind of sucks, we rebuild the tag tables //
//      from scratch for *every* proxy.config.diags value that changed; //
//      dgourley is looking into changing the management API to provide //
//      a callback each time records.yaml changed, possibly better.   //
//
//////////////////////////////////////////////////////////////////////////////
void
DiagsConfig::register_diags_callbacks()
{
  static const char *config_record_names[] = {
    "proxy.config.diags.debug.enabled",  "proxy.config.diags.debug.tags",       "proxy.config.diags.action.enabled",
    "proxy.config.diags.action.tags",    "proxy.config.diags.show_location",    "proxy.config.diags.output.diag",
    "proxy.config.diags.output.debug",   "proxy.config.diags.output.status",    "proxy.config.diags.output.note",
    "proxy.config.diags.output.warning", "proxy.config.diags.output.error",     "proxy.config.diags.output.fatal",
    "proxy.config.diags.output.alert",   "proxy.config.diags.output.emergency", nullptr,
  };

  bool  total_status = true;
  bool  status;
  int   i;
  void *o = (void *)this;

  // set triggers to call same callback for any diag config change
  for (i = 0; config_record_names[i] != nullptr; i++) {
    status = (RecRegisterConfigUpdateCb(config_record_names[i], diags_config_callback, o) == REC_ERR_OKAY);
    if (!status) {
      Warning("couldn't register variable '%s', is %s up to date?", config_record_names[i], ts::filename::RECORDS);
    }
    total_status = total_status && status;
  }

  if (total_status == false) {
    Error("couldn't setup all diags callbacks, diagnostics may misbehave");
    callbacks_established = false;
  } else {
    callbacks_established = true;
  }
}

DiagsConfig::~DiagsConfig() {}
