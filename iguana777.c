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

void iguana_coinloop(void *arg)
{
    int32_t flag,i,n,m; uint32_t now,lastdisp = 0; struct iguana_info *coin,**coins = arg;
    n = (int32_t)(long)coins[0];
    coins++;
    printf("begin coinloop[%d]\n",n);
    for (i=0; i<n; i++)
    {
        if ( (coin= coins[i]) != 0 && coin->started == 0 )
        {
            iguana_startcoin(coin,coin->initialheight,coin->mapflags);
            coin->started = coin;
            coin->chain->minconfirms = coin->minconfirms;
        }
    }
    coin = coins[0];
    iguana_possible_peer(coin,"127.0.0.1");
    while ( 1 )
    {
        flag = 0;
        for (i=0; i<n; i++)
        {
            if ( (coin= coins[i]) != 0 )
            {
                now = (uint32_t)time(NULL);
                if ( now > coin->lastpossible )
                    coin->lastpossible = iguana_possible_peer(coin,0); // tries to connect to new peers
                if ( now > coin->peers.lastmetrics+60 )
                    coin->peers.lastmetrics = iguana_updatemetrics(coin); // ranks peers
                flag += iguana_updatebundles(coin);
                if ( 0 && coin->blocks.parsedblocks < coin->blocks.hwmheight-coin->chain->minconfirms )
                {
                    if ( iguana_updateramchain(coin) != 0 )
                        iguana_syncs(coin), flag++; // merge ramchain fragments into full ramchain
                }
            }
        }
        if ( now > lastdisp+1 )
        {
            lastdisp = (uint32_t)now;
            for (i=m=0; i<coin->longestchain; i++)
                if ( iguana_havehash(coin,i) > 0 )
                    m++;
            printf("%s.%d: pend.%d/%d hash.%d/%d I.%d recv.%d/%d emit.%d HWM.%d parsed.%d |long.%d %.2f min\n",coin->symbol,flag,coin->numpendings,coin->hdrscount,coin->blocks.hashblocks,m,coin->blocks.issuedblocks,coin->blocks.recvblocks,coin->recvcount,coin->blocks.emitblocks,coin->blocks.hwmheight,coin->blocks.parsedblocks,coin->longestchain,(double)(time(NULL)-coin->starttime)/60.);
            if ( (rand() % 60) == 0 )
                myallocated();
        }
        if ( flag == 0 )
            usleep(5000);
    }
}

void iguana_coinargs(char *symbol,int64_t *maxrecvcachep,int32_t *minconfirmsp,int32_t *maxpeersp,int32_t *initialheightp,uint64_t *servicesp,cJSON *json)
{
    if ( (*maxrecvcachep= j64bits(json,"maxrecvcache")) != 0 )
        *maxrecvcachep *= 1024 * 1024 * 1024L;
    *minconfirmsp = juint(json,"minconfirms");
    *maxpeersp= juint(json,"maxpeers");
    if ( (*initialheightp= juint(json,"initialheight")) == 0 )
        *initialheightp = (strcmp(symbol,"BTC") == 0) ? 400000 : 100000;
    *servicesp = j64bits(json,"services");
}

struct iguana_info *iguana_setcoin(char *symbol,void *launched,int32_t maxpeers,int64_t maxrecvcache,uint64_t services,int32_t initialheight,int32_t maphash,int32_t minconfirms)
{
    struct iguana_info *coin; int32_t mapflags; char dirname[512];
    mapflags = IGUANA_MAPRECVDATA | maphash*IGUANA_MAPTXIDITEMS | maphash*IGUANA_MAPPKITEMS | maphash*IGUANA_MAPBLOCKITEMS | maphash*IGUANA_MAPPEERITEMS;
    coin = iguana_coin(symbol);
    coin->launched = launched;
    if ( (coin->MAXPEERS= maxpeers) <= 0 )
        maxpeers = (strcmp(symbol,"BTC") == 0) ? 128 : 32;
    if ( (coin->MAXRECVCACHE= maxrecvcache) == 0 )
        coin->MAXRECVCACHE = IGUANA_MAXRECVCACHE;
    coin->myservices = services;
    sprintf(dirname,"DB/%s",symbol);
    ensure_directory(dirname);
    sprintf(dirname,"tmp/%s",symbol);
    ensure_directory(dirname);
    coin->initialheight = initialheight;
    coin->mapflags = mapflags;
    if ( (coin->minconfirms = minconfirms) == 0 )
        coin->minconfirms = (strcmp(symbol,"BTC") == 0) ? 3 : 10;
    return(coin);
}

int32_t iguana_launchcoin(char *symbol,cJSON *json)
{
    int32_t maxpeers,maphash,initialheight,minconfirms; int64_t maxrecvcache; uint64_t services;
    struct iguana_info **coins,*coin;
    if ( symbol == 0 )
        return(-1);
    if ( (coin= iguana_coin(symbol)) == 0 )
        return(-1);
    if ( coin->launched == 0 )
    {
        if ( juint(json,"GBavail") < 8 )
            maphash = IGUANA_MAPHASHTABLES;
        else maphash = 0;
        iguana_coinargs(symbol,&maxrecvcache,&minconfirms,&maxpeers,&initialheight,&services,json);
        coins = mycalloc('A',1+1,sizeof(*coins));
        if ( (coin= iguana_setcoin(coin->symbol,coins,maxpeers,maxrecvcache,services,initialheight,maphash,minconfirms)) != 0 )
        {
            coins[0] = (void *)((long)1);
            coins[1] = coin;
            printf("launch coinloop for.%s\n",coin->symbol);
            iguana_launch("iguana_coinloop",iguana_coinloop,coins,IGUANA_PERMTHREAD);
            return(1);
        }
        else
        {
            myfree(coins,sizeof(*coins) * 2);
            return(-1);
        }
    }
    return(0);
}

void iguana_coins(void *arg)
{
    struct iguana_chain *iguana_createchain(cJSON *json);
    struct iguana_info **coins,*coin; char *jsonstr,*symbol; cJSON *array,*item,*json,*peers;
    int32_t i,j,n,m,maxpeers,maphash,initialheight,minconfirms; int64_t maxrecvcache; uint64_t services;
    if ( (jsonstr= arg) != 0 && (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( (array= jarray(&n,json,"coins")) == 0 )
        {
            if ( (symbol= jstr(json,"coin")) != 0 && strncmp(symbol,"BTC",3) == 0 )
            {
                coins = mycalloc('A',1+1,sizeof(*coins));
                coins[1] = iguana_setcoin(symbol,coins,0,0,0,0,0,0);
                coins[0] = (void *)((long)1);
                iguana_coinloop(coins);
            } else printf("no coins[] array in JSON.(%s) only BTCD and BTC can be quicklaunched\n",jsonstr);
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
            iguana_coinargs(symbol,&maxrecvcache,&minconfirms,&maxpeers,&initialheight,&services,item);
            printf("init.(%s) maxpeers.%d maxrecvcache.%s maphash.%x services.%llx\n",symbol,maxpeers,mbstr(maxrecvcache),maphash,(long long)services);
            coins[1 + i] = coin = iguana_setcoin(symbol,coins,maxpeers,maxrecvcache,services,initialheight,maphash,minconfirms);
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
            printf("MAXRECVCACHE.%s\n",mbstr(coin->MAXRECVCACHE));
        }
        coins[0] = (void *)((long)n);
        iguana_coinloop(coins);
    }
}
