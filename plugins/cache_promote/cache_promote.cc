/*
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
#include <cstdio>
#include <cstring>

#include "ts/ts.h"
#include "ts/remap.h"
#include "ts/remap_version.h"

#include "policy_manager.h"
#include "configs.h"

const char *PLUGIN_NAME = "cache_promote";
int         TXN_ARG_IDX;
DbgCtl      cache_promote_dbg_ctl{PLUGIN_NAME};

// This has to be a global here. I tried doing a classic singleton (with a getInstance()) in the PolicyManager,
// but then reloading the DSO does not work. What happens is that the old singleton is still there, even though
// the rest of the plugin is reloaded. Very scary, and not what we need / want; if the plugin reloads, the
// PolicyManager has to reload (and start fresh) as well.
static PolicyManager gManager;

//////////////////////////////////////////////////////////////////////////////////////////////
// Main "plugin", a TXN hook in the TS_HTTP_READ_CACHE_HDR_HOOK. Unless the policy allows
// caching, we will turn off the cache from here on for the TXN.
//
// NOTE: This is not optimal, the goal was to handle this before we lock the URL in the
// cache. However, that does not work. Hence, for now, we also schedule the continuation
// for READ_RESPONSE_HDR such that we can turn off  the actual cache write.
//
static int
cont_handle_policy(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn        txnp   = static_cast<TSHttpTxn>(edata);
  PromotionConfig *config = static_cast<PromotionConfig *>(TSContDataGet(contp));

  switch (event) {
  // After the cache lookups check if it should be promoted on cache misses
  case TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE:
    if (!TSHttpTxnIsInternal(txnp) || config->getPolicy()->isInternalEnabled()) {
      int obj_status;

      if (TS_ERROR != TSHttpTxnCacheLookupStatusGet(txnp, &obj_status)) {
        switch (obj_status) {
        case TS_CACHE_LOOKUP_MISS:
        case TS_CACHE_LOOKUP_SKIPPED:
          if (config->getPolicy()->doSample() && config->getPolicy()->doPromote(txnp)) {
            DBG("cache-status is %d, and leaving cache on (promoted)", obj_status);
          } else {
            DBG("cache-status is %d, and turning off the cache (not promoted)", obj_status);
            if (config->getPolicy()->countBytes()) {
              // Need to schedule this continuation for read-response-header-hook as well.
              TSHttpTxnHookAdd(txnp, TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
              // This is needed to make sure that we free any data retained in the TXN slot even if the
              // transaction is terminated early.
              TSHttpTxnHookAdd(txnp, TS_HTTP_TXN_CLOSE_HOOK, contp);
            }
            TSHttpTxnCntlSet(txnp, TS_HTTP_CNTL_SERVER_NO_STORE, true);
          }
          break;
        default:
          // Do nothing, just let it handle the lookup.
          DBG("cache-status is %d (hit), nothing to do", obj_status);

          if (!config->getPolicy()->_stats_id.empty()) {
            TSStatIntIncrement(config->getPolicy()->_cache_hits_id, 1);
          }
          break;
        }
      }
      if (!config->getPolicy()->_stats_id.empty()) {
        TSStatIntIncrement(config->getPolicy()->_total_requests_id, 1);
      }
    } else {
      DBG("request is an internal (plugin) request, implicitly promoted");
    }
    break;

  // This is the event when we want to count the bytes cache miss as well as hits
  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    config->getPolicy()->addBytes(txnp);
    break;

  case TS_EVENT_HTTP_TXN_CLOSE:
    config->getPolicy()->cleanup(txnp);
    break;

  // Should not happen
  default:
    DBG("unhandled event %d", static_cast<int>(event));
    break;
  }

  // Reenable and continue with the state machine.
  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Initialize the plugin as a remap plugin.
//
TSReturnCode
TSRemapInit(TSRemapInterface *api_info, char *errbuf, int errbuf_size)
{
  CHECK_REMAP_API_COMPATIBILITY(api_info, errbuf, errbuf_size);

  // Reserve a TXN slot for storing the calculated URL hash key
  if (TS_SUCCESS != TSUserArgIndexReserve(TS_USER_ARGS_TXN, PLUGIN_NAME, "cache_promote URL hash key", &TXN_ARG_IDX)) {
    strncpy(errbuf, "[tsremap_init] - Failed to reserve the TXN user argument slot", errbuf_size - 1);
    return TS_ERROR;
  }

  DBG("remap plugin is successfully initialized, TXN_IDX = %d", TXN_ARG_IDX);
  return TS_SUCCESS; /* success */
}

void
TSRemapDone()
{
  DBG("called TSRemapDone()");
  gManager.clear();
}

TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **ih, char * /* errbuf */, int /* errbuf_size */)
{
  PromotionConfig *config = new PromotionConfig(&gManager);

  --argc;
  ++argv;
  if (config->factory(argc, argv)) {
    TSCont contp = TSContCreate(cont_handle_policy, nullptr);

    TSContDataSet(contp, static_cast<void *>(config));
    *ih = static_cast<void *>(contp);

    return TS_SUCCESS;
  } else {
    delete config;
    return TS_ERROR;
  }
}

void
TSRemapDeleteInstance(void *ih)
{
  TSCont           contp  = static_cast<TSCont>(ih);
  PromotionConfig *config = static_cast<PromotionConfig *>(TSContDataGet(contp));

  delete config; // This will return the PromotionPolicy to the PromotionManager as well
  TSContDestroy(contp);
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Schedule the cache-read continuation for this remap rule.
//
TSRemapStatus
TSRemapDoRemap(void *ih, TSHttpTxn rh, TSRemapRequestInfo * /* ATS_UNUSED rri */)
{
  if (nullptr == ih) {
    DBG("no promotion rules configured, this is probably a plugin bug");
  } else {
    TSCont contp = static_cast<TSCont>(ih);

    DBG("scheduling a TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK hook");
    TSHttpTxnHookAdd(rh, TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, contp);
  }

  return TSREMAP_NO_REMAP;
}
