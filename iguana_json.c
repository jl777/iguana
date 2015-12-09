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

struct iguana_jsonitem { struct queueitem DL; uint32_t expired,allocsize; char **retjsonstrp; char jsonstr[]; };

queue_t finishedQ,helperQ;
static struct iguana_info Coins[64];
const char *Hardcoded_coins[][3] = { { "BTC", "bitcoin", "0" }, { "BTCD", "BitcoinDark", "129" } };

struct iguana_info *iguana_coin(const char *symbol)
{
    struct iguana_info *coin; int32_t i = 0;
    if ( symbol == 0 )
    {
        for (i=sizeof(Hardcoded_coins)/sizeof(*Hardcoded_coins); i<sizeof(Coins)/sizeof(*Coins); i++)
        {
            if ( Coins[i].symbol[0] == 0 )
            {
                memset(&Coins[i],0,sizeof(Coins[i]));
                printf("iguana_coin.(new) -> %p\n",&Coins[i]);
                return(&Coins[i]);
            } return(0);
            printf("i.%d (%s) vs name.(%s)\n",i,Coins[i].name,symbol);
        }
    }
    else
    {
        for (i=0; i<sizeof(Hardcoded_coins)/sizeof(*Hardcoded_coins); i++)
        {
            coin = &Coins[i];
            if ( strcmp(symbol,Hardcoded_coins[i][0]) == 0 )
            {
                if ( coin->chain == 0 )
                {
                    strcpy(coin->name,Hardcoded_coins[i][1]);
                    coin->myservices = atoi(Hardcoded_coins[i][2]);
                    strcpy(coin->symbol,symbol);
                    coin->chain = iguana_chainfind(coin->symbol);
                    iguana_initcoin(coin);
                }
                return(coin);
            }
        }
    }
    return(0);
}

char *iguana_genericjson(char *method,cJSON *json)
{
    return(clonestr("{\"result\":\"process generic json\"}"));
}

char *iguana_json(struct iguana_info *coin,char *method,cJSON *json)
{
    return(clonestr("{\"result\":\"process iguana json\"}"));
}

char *iguana_jsonstr(struct iguana_info *coin,char *jsonstr)
{
    cJSON *json; char *retjsonstr,*methodstr;
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( (methodstr= jstr(json,"method")) != 0 )
            retjsonstr = iguana_json(coin,methodstr,json);
        else retjsonstr = clonestr("{\"error\":\"no method in JSON\"}");
        free_json(json);
    } else retjsonstr = clonestr("{\"error\":\"cant parse JSON\"}");
    return(retjsonstr);
}

char *iguana_genericjsonstr(char *jsonstr)
{
    cJSON *json; char *retjsonstr,*methodstr;
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( (methodstr= jstr(json,"method")) != 0 )
            retjsonstr = iguana_genericjson(methodstr,json);
        else retjsonstr = clonestr("{\"error\":\"no method in generic JSON\"}");
        free_json(json);
    } else retjsonstr = clonestr("{\"error\":\"cant parse generic JSON\"}");
    return(retjsonstr);
}

int32_t iguana_processjsonQ(struct iguana_info *coin) // reentrant, can be called during any idletime
{
    struct iguana_jsonitem *ptr;
    if ( (ptr= queue_dequeue(&finishedQ,0)) != 0 )
    {
        if ( ptr->expired != 0 )
        {
            printf("garbage collection: expired.(%s)\n",ptr->jsonstr);
            myfree(ptr,ptr->allocsize);
        } else queue_enqueue("finishedQ",&finishedQ,&ptr->DL,0);
    }
    if ( (ptr= queue_dequeue(&coin->jsonQ,0)) != 0 )
    {
        if ( (*ptr->retjsonstrp= iguana_jsonstr(coin,ptr->jsonstr)) == 0 )
            *ptr->retjsonstrp = clonestr("{\"error\":\"null return from iguana_jsonstr\"}");
        queue_enqueue("finishedQ",&finishedQ,&ptr->DL,0);
        return(1);
    }
    return(0);
}

char *iguana_blockjsonstr(struct iguana_info *coin,char *jsonstr,uint64_t tag,int32_t maxmillis)
{
    struct iguana_jsonitem *ptr; char *retjsonstr; int32_t len,allocsize; double expiration = milliseconds() + maxmillis;
    if ( coin == 0 )
        return(iguana_genericjsonstr(jsonstr));
    else
    {
        len = (int32_t)strlen(jsonstr);
        allocsize = sizeof(*ptr) + len + 1;
        ptr = mycalloc('J',1,allocsize);
        ptr->allocsize = allocsize;
        ptr->retjsonstrp = &retjsonstr;
        memcpy(ptr->jsonstr,jsonstr,len+1);
        queue_enqueue("jsonQ",&coin->jsonQ,&ptr->DL,0);
        while ( milliseconds() < expiration )
        {
            usleep(100);
            if ( (retjsonstr= *ptr->retjsonstrp) != 0 )
            {
                queue_delete(&finishedQ,&ptr->DL,allocsize,1);
                return(retjsonstr);
            }
            usleep(1000);
        }
        printf("(%s) expired\n",jsonstr);
        ptr->expired = (uint32_t)time(NULL);
        return(clonestr("{\"error\":\"iguana jsonstr expired\"}"));
    }
}

char *iguana_JSON(char *jsonstr)
{
    cJSON *json,*retjson; uint64_t tag; uint32_t timeout; struct iguana_info *coin; char *retjsonstr,*symbol,*retstr = 0;
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( (tag= j64bits(json,"tag")) == 0 )
            randombytes((uint8_t *)&tag,sizeof(tag));
        if ( (symbol= jstr(json,"coin")) != 0 )
            coin = iguana_coin(symbol);
        else coin = 0;
        if ( (timeout= juint(json,"timeout")) == 0 )
            timeout = IGUANA_JSONTIMEOUT;
        if ( (retjsonstr= iguana_blockjsonstr(coin,jsonstr,tag,timeout)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retjsonstr)) == 0 )
                retjson = cJSON_Parse("{\"error\":\"cant parse retjsonstr\"}");
            jdelete(retjson,"tag");
            jadd64bits(retjson,"tag",tag);
            retstr = jprint(retjson,1);
            free(retjsonstr);//,strlen(retjsonstr)+1);
        }
        free_json(json);
    } else retstr = clonestr("{\"error\":\"cant parse JSON\"}");
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"null return\"}");
    return(retstr);
}

void iguana_issuejsonstrM(void *arg)
{
    cJSON *json; int32_t fd; char *retjsonstr,*jsonstr = arg;
    retjsonstr = iguana_JSON(jsonstr);
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( (fd= juint(json,"retdest")) > 0 )
        {
            send(fd,jsonstr,(int32_t)strlen(jsonstr)+1,MSG_NOSIGNAL);
        }
        free_json(json);
        return;
    }
    printf("%s\n",retjsonstr);
    myfree(retjsonstr,strlen(retjsonstr)+1);
    myfree(jsonstr,strlen(jsonstr)+1);
}

void iguana_coins(void *arg)
{
    struct iguana_chain *iguana_createchain(cJSON *json);
    struct iguana_info **coins,*coin; char dirname[512],*jsonstr,*symbol; cJSON *array,*item,*json,*peers;
    int32_t i,j,n,m,maxpeers,mapflags,maphash,initialheight,minconfirms; int64_t maxrecvcache; uint64_t services;
    if ( (jsonstr= arg) != 0 && (json= cJSON_Parse(jsonstr)) != 0 )
    {
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
            if ( (maxrecvcache= j64bits(item,"maxrecvcache")) == 0 )
                maxrecvcache = IGUANA_MAXRECVCACHE;
            else maxrecvcache *= 1024 * 1024 * 1024L;
            mapflags = IGUANA_MAPRECVDATA | maphash*IGUANA_MAPTXIDITEMS | maphash*IGUANA_MAPPKITEMS | maphash*IGUANA_MAPBLOCKITEMS | maphash*IGUANA_MAPPEERITEMS;
            if ( (minconfirms= juint(item,"minconfirms")) <= 0 )
                minconfirms = (strcmp(symbol,"BTC") == 0) ? 3 : 10;
            if ( (maxpeers= juint(item,"maxpeers")) == 0 )
                maxpeers = (strcmp(symbol,"BTC") == 0) ? 128 : 32;
            if ( (initialheight= juint(item,"initialheight")) == 0 )
                initialheight = (strcmp(symbol,"BTC") == 0) ? 400000 : 100000;
            services = j64bits(item,"services");
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
            coin->chain->minconfirms = minconfirms;
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

void iguana_helper(void *arg)
{
    int32_t flag; void *ptr; queue_t *Q = arg;
    printf("start helper\n");
    while ( 1 )
    {
        flag = 0;
        if ( (ptr= queue_dequeue(Q,0)) != 0 )
        {
            printf("START emittxdata\n");
            //iguana_emittxdata(bp->coin,bp);
            flag++;
            printf("FINISH emittxdata\n");
        }
    }
    if ( flag == 0 )
        sleep(1);
}

void iguana_main(void *arg)
{
    int32_t i,len,flag; cJSON *json; uint8_t secretbuf[512]; char *coinargs,*secret,*jsonstr = arg;
    //  portable_OS_init()?
    mycalloc(0,0,0);
    iguana_initQ(&helperQ,"helperQ");
    ensure_directory("DB");
    ensure_directory("tmp");
    iguana_JSON("{}");
    if ( jsonstr != 0 && (json= cJSON_Parse(jsonstr)) != 0 )
    {
        IGUANA_NUMHELPERS = juint(json,"numhelpers");
        if ( (secret= jstr(json,"secret")) != 0 )
        {
            len = (int32_t)strlen(secret);
            if ( is_hexstr(secret) != 0 && len <= (sizeof(secretbuf)<<1) )
            {
                len >>= 1;
                decode_hex(secretbuf,len,secret);
            } else vcalc_sha256(0,secretbuf,(void *)secret,len), len = sizeof(bits256);
        }
        if ( jobj(json,"coins") != 0 )
            coinargs = jsonstr;
    }
    if ( IGUANA_NUMHELPERS == 0 )
    {
#ifdef __linux__
        IGUANA_NUMHELPERS = 8;
#else
        IGUANA_NUMHELPERS = 1;
#endif
    }
    for (i=0; i<IGUANA_NUMHELPERS; i++)
        iguana_launch("helpers",iguana_helper,&helperQ,IGUANA_HELPERTHREAD);
    if ( coinargs != 0 )
        iguana_launch("coinmain",iguana_coins,coinargs,IGUANA_PERMTHREAD);
    while ( 1 )
    {
        flag = 0;
        for (i=0; i<sizeof(Coins)/sizeof(*Coins); i++)
            if ( Coins[i].symbol[0] != 0 )
                flag += iguana_processjsonQ(&Coins[i]);
        if ( flag == 0 )
            usleep(100000);
    }
}
