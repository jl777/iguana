/******************************************************************************
 * Copyright © 2014-2015 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#include "iguana777.h"

char *iguana_rpc(struct iguana_info *coin,char *jsonstr)
{
    return(clonestr("{\"returned jsonstr might not be json for some calls, needs to be 100% backward compatible with BTC RPC\"}"));
}

int32_t iguana_rpctestvector(struct iguana_info *coin,char *checkstr,char *jsonstr,int32_t maxlen,int32_t testi)
{
    int32_t len,checklen;
    sprintf(jsonstr,"{\"rpc.%s testvector.%d\"}",coin->symbol,testi);
    sprintf(checkstr,"{\"rpc.%s testvector.%d checkstr should have all info needed to verify the rpc request\"}",coin->symbol,testi);
    len = (int32_t)strlen(jsonstr);
    checklen = (int32_t)strlen(checkstr);
    if ( len > maxlen || checklen > maxlen )
        printf("iguana_rpctestvector: i was bad and overflowed buffer len.%d checklen.%d\n",len,checklen), exit(-1);
    if ( checklen > len )
        len = checklen;
    return(len);
}

int32_t iguana_rpctestcheck(struct iguana_info *coin,char *jsonstr,char *retjsonstr)
{
    if ( (rand() % 100) == 0 ) // 1% failure rate
        return(-1);
    else return(0);
}

int32_t iguana_rpctest(struct iguana_info *coin)
{
    static int32_t testi,good,bad;
    char *retjsonstr,jsonstr[4096],checkstr[sizeof(jsonstr)]; // should be big enough
    if ( (rand() & 1) == 0 ) // if no test active, just return 0
        return(0);
    if ( iguana_rpctestvector(coin,checkstr,jsonstr,sizeof(jsonstr),testi++) > 0 )
    {
        retjsonstr = iguana_rpc(coin,jsonstr);
        if ( iguana_rpctestcheck(coin,jsonstr,retjsonstr) < 0 )
            bad++, printf("rpctestcheck.%s error: (%s) -> (%s) | good.%d bad.%d %.2f%%\n",coin->symbol,jsonstr,retjsonstr,good,bad,100.*(double)good/(good+bad));
        else good++;
        free(retjsonstr);
        return(1); // indicates was active
    }
    return(0);
}