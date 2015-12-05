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

cJSON *process_iguana_method(char *methodstr,cJSON *json)
{
    return(cJSON_Parse("{\"result\":\"unsupported method\"}"));
}

char *iguana_JSON(char *jsonstr)
{
    cJSON *json,*retjson; uint64_t tag; char *methodstr,*retstr = 0;
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( (methodstr= jstr(json,"method")) != 0 )
        {
            if ( (tag= j64bits(json,"tag")) == 0 )
                randombytes((uint8_t *)&tag,sizeof(tag));
            retjson = process_iguana_method(methodstr,json);
            jdelete(retjson,"tag");
            jadd64bits(retjson,"tag",tag);
            retstr = jprint(retjson,1);
        }
        free_json(json);
    }
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"null return\"}");
    return(retstr);
}

void iguana_main(void *arg)
{
    struct iguana_chain *iguana_createchain(cJSON *json);
    struct iguana_info **coins,*coin; char dirname[512],*jsonstr,*symbol; cJSON *array,*item,*json,*peers;
    int32_t i,j,n,m,maxpeers,mapflags,maphash,initialheight; int64_t maxrecvcache; uint64_t services;
    if ( (jsonstr= arg) == 0 )
    {
        printf("null JSON sent to iguana_main\n");
        return;
    }
    if ( (json= cJSON_Parse(jsonstr)) == 0 )
    {
        printf("unparseable JSON.(%s) sent to iguana_main\n",jsonstr);
        return;
    }
    mycalloc(0,0,0);
    ensure_directory("DB");
    ensure_directory("tmp");
    if ( (array= jarray(&n,json,"coins")) == 0 )
    {
        printf("no coins[] array in JSON.(%s) sent to iguana_main\n",jsonstr);
        free_json(json);
        return;
    }
    coins = mycalloc('A',n+1,sizeof(*coins));
    if ( juint(json,"GBavail") < 8 )
        maphash = IGUANA_MAPHASHTABLES;
    else maphash = 0;
    printf("MAPHASH.%d\n",maphash);
    for (i=0; i<n; i++)
    {
        item = jitem(array,i);
        if ( (symbol= jstr(item,"name")) == 0 || strlen(symbol) > 8 )
        {
            printf("skip strange coin.(%s)\n",symbol);
            continue;
        } 
        sprintf(dirname,"DB/%s",symbol);
        ensure_directory(dirname);
        sprintf(dirname,"tmp/%s",symbol);
        ensure_directory(dirname);
        if ( (maxrecvcache= j64bits(json,"maxrecvcache")) == 0 )
            maxrecvcache = IGUANA_MAXRECVCACHE;
        else maxrecvcache *= 1024 * 1024 * 1024L;
        mapflags = IGUANA_MAPRECVDATA | maphash*IGUANA_MAPTXIDITEMS | maphash*IGUANA_MAPPKITEMS | maphash*IGUANA_MAPBLOCKITEMS | maphash*IGUANA_MAPPEERITEMS;
        if ( (maxpeers= juint(json,"maxpeers")) == 0 )
            maxpeers = (strcmp(symbol,"BTC") == 0) ? 128 : 32;
        if ( (initialheight= juint(json,"initialheight")) == 0 )
            initialheight = (strcmp(symbol,"BTC") == 0) ? 400000 : 100000;
        services = j64bits(json,"services");
        printf("init.(%s) maxpeers.%d maxrecvcache.%s mapflags.%x services.%llx\n",symbol,maxpeers,mbstr(maxrecvcache),mapflags,(long long)services);
        coin = iguana_coin(symbol);
        coin->MAXPEERS = maxpeers;
        coin->MAXRECVCACHE = maxrecvcache;
        coin->myservices = services;
        coins[1 + i] = iguana_startcoin(coin,initialheight,mapflags);
        if ( coin->chain == 0 && (coin->chain= iguana_createchain(item)) == 0 )
        {
            printf("cant initialize chain.(%s)\n",jstr(item,0));
            coins[1 + i] = 0;
            continue;
        }
        if ( (peers= jarray(&m,item,"peers")) != 0 )
        {
            for (j=0; j<m; j++)
            {
                printf("%s ",jstr(jitem(peers,j),0));
                iguana_possible_peer(coin,jstr(jitem(peers,j),0));
            }
            printf("addnodes.%d\n",m);
        }
    }
    coins[0] = (void *)((long)n);
    iguana_coinloop(coins);
}
