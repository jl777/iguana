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

int32_t iguana_launchcoin(char *symbol,cJSON *json);
struct iguana_jsonitem { struct queueitem DL; uint32_t expired,allocsize; char **retjsonstrp; char jsonstr[]; };

struct iguana_info *iguana_coin(const char *symbol)
{
    struct iguana_info *coin; int32_t i = 0;
    if ( symbol == 0 )
    {
        for (i=0; i<sizeof(Coins)/sizeof(*Coins); i++)
            if ( Hardcoded_coins[i][0] == 0 )
                break;
        for (; i<sizeof(Coins)/sizeof(*Coins); i++)
        {
            if ( Coins[i] == 0 )
            {
                Coins[i] = mycalloc('c',1,sizeof(*Coins[i]));
                //memset(Coins[i],0,sizeof(*Coins[i]));
                printf("iguana_coin.(new) -> %p\n",Coins[i]);
                return(Coins[i]);
            } return(0);
            printf("i.%d (%s) vs name.(%s)\n",i,Coins[i]->name,symbol);
        }
    }
    else
    {
        for (i=0; i<sizeof(Coins)/sizeof(*Coins); i++)
        {
            if ( Hardcoded_coins[i][0] == 0 )
                break;
            if ( strcmp(symbol,Hardcoded_coins[i][0]) == 0 )
            {
                if ( Coins[i] == 0 )
                    Coins[i] = mycalloc('c',1,sizeof(*Coins[i]));
                coin = Coins[i];
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

cJSON *iguana_peerjson(struct iguana_info *coin,struct iguana_peer *addr)
{
    cJSON *array,*json = cJSON_CreateObject();
    jaddstr(json,"ipaddr",addr->ipaddr);
    jaddnum(json,"protover",addr->protover);
    jaddnum(json,"relay",addr->relayflag);
    jaddnum(json,"height",addr->height);
    jaddnum(json,"rank",addr->rank);
    jaddnum(json,"usock",addr->usock);
    if ( addr->dead != 0 )
        jaddnum(json,"dead",addr->dead);
    jaddnum(json,"ready",addr->ready);
    jaddnum(json,"recvblocks",addr->recvblocks);
    jaddnum(json,"recvtotal",addr->recvtotal);
    jaddnum(json,"lastcontact",addr->lastcontact);
    if ( addr->numpings > 0 )
        jaddnum(json,"aveping",addr->pingsum/addr->numpings);
    array = cJSON_CreateObject();
    jaddnum(array,"version",addr->msgcounts.version);
    jaddnum(array,"verack",addr->msgcounts.verack);
    jaddnum(array,"getaddr",addr->msgcounts.getaddr);
    jaddnum(array,"addr",addr->msgcounts.addr);
    jaddnum(array,"inv",addr->msgcounts.inv);
    jaddnum(array,"getdata",addr->msgcounts.getdata);
    jaddnum(array,"notfound",addr->msgcounts.notfound);
    jaddnum(array,"getblocks",addr->msgcounts.getblocks);
    jaddnum(array,"getheaders",addr->msgcounts.getheaders);
    jaddnum(array,"headers",addr->msgcounts.headers);
    jaddnum(array,"tx",addr->msgcounts.tx);
    jaddnum(array,"block",addr->msgcounts.block);
    jaddnum(array,"mempool",addr->msgcounts.mempool);
    jaddnum(array,"ping",addr->msgcounts.ping);
    jaddnum(array,"pong",addr->msgcounts.pong);
    jaddnum(array,"reject",addr->msgcounts.reject);
    jaddnum(array,"filterload",addr->msgcounts.filterload);
    jaddnum(array,"filteradd",addr->msgcounts.filteradd);
    jaddnum(array,"filterclear",addr->msgcounts.filterclear);
    jaddnum(array,"merkleblock",addr->msgcounts.merkleblock);
    jaddnum(array,"alert",addr->msgcounts.alert);
    jadd(json,"msgcounts",array);
    return(json);
}

cJSON *iguana_peersjson(struct iguana_info *coin)
{
    cJSON *retjson,*array; int32_t i; struct iguana_peer *addr;
    retjson = cJSON_CreateObject();
    array = cJSON_CreateArray();
    for (i=0; i<coin->MAXPEERS; i++)
    {
        addr = &coin->peers.active[i];
        if ( addr->usock >= 0 && addr->ipbits != 0 && addr->ipaddr[0] != 0 )
            jaddi(array,iguana_peerjson(coin,addr));
    }
    jadd(retjson,"peers",array);
    jaddnum(retjson,"maxpeers",coin->MAXPEERS);
    jaddstr(retjson,"coin",coin->symbol);
    return(retjson);
}

char *iguana_genericjson(char *method,cJSON *json)
{
    cJSON *retjson,*array; int32_t i;
    if ( strcmp(method,"list") == 0 )
    {
        retjson = cJSON_CreateObject();
        array = cJSON_CreateArray();
        for (i=0; i<sizeof(Coins)/sizeof(*Coins); i++)
        {
            if ( Coins[i] != 0 && Coins[i]->symbol[0] != 0 )
                jaddistr(array,Coins[i]->symbol);
        }
        jadd(retjson,"coins",array);
        return(jprint(retjson,1));
    }
    if ( strcmp(method,"peers") == 0 )
    {
        retjson = cJSON_CreateObject();
        array = cJSON_CreateArray();
        for (i=0; i<sizeof(Coins)/sizeof(*Coins); i++)
        {
            if ( Coins[i] != 0 && Coins[i]->symbol[0] != 0 )
                jaddi(array,iguana_peersjson(Coins[i]));
        }
        jadd(retjson,"allpeers",array);
        return(jprint(retjson,1));
    }
    return(clonestr("{\"result\":\"stub processed generic json\"}"));
}

char *iguana_json(struct iguana_info *coin,char *method,cJSON *json)
{
    int32_t i,max,retval; struct iguana_peer *addr; char *ipaddr; cJSON *retjson = 0;
    if ( strcmp(method,"peers") == 0 )
        return(jprint(iguana_peersjson(coin),1));
    else if ( strcmp(method,"addnode") == 0 )
    {
        if ( (ipaddr= jstr(json,"ipaddr")) != 0 )
        {
            iguana_possible_peer(coin,ipaddr);
            return(clonestr("{\"result\":\"addnode submitted\"}"));
        } else return(clonestr("{\"error\":\"addnode needs ipaddr\"}"));
    }
    else if ( strcmp(method,"nodestatus") == 0 )
    {
        if ( (ipaddr= jstr(json,"ipaddr")) != 0 )
        {
            for (i=0; i<coin->MAXPEERS; i++)
            {
                addr = &coin->peers.active[i];
                if ( strcmp(addr->ipaddr,ipaddr) == 0 )
                    return(jprint(iguana_peerjson(coin,addr),1));
            }
            return(clonestr("{\"result\":\"nodestatus couldnt find ipaddr\"}"));
        } else return(clonestr("{\"error\":\"nodestatus needs ipaddr\"}"));
    }
    else if ( strcmp(method,"maxpeers") == 0 )
    {
        retjson = cJSON_CreateObject();
        if ( (max= juint(json,"max")) <= 0 )
            max = 1;
        else if ( max > IGUANA_MAXPEERS )
            max = IGUANA_MAXPEERS;
        if ( max > coin->MAXPEERS )
        {
            for (i=max; i<coin->MAXPEERS; i++)
                if ( (addr= coin->peers.ranked[i]) != 0 )
                    addr->dead = 1;
        }
        coin->MAXPEERS = max;
        jaddnum(retjson,"maxpeers",coin->MAXPEERS);
        jaddstr(retjson,"coin",coin->symbol);
        return(jprint(retjson,1));
    }
    else if ( strcmp(method,"startcoin") == 0 )
    {
        coin->active = 1;
        return(clonestr("{\"result\":\"coin started\"}"));
    }
    else if ( strcmp(method,"pausecoin") == 0 )
    {
        coin->active = 1;
        return(clonestr("{\"result\":\"coin paused\"}"));
    }
    else if ( strcmp(method,"addcoin") == 0 )
    {
        if ( (retval= iguana_launchcoin(coin->symbol,json)) > 0 )
            return(clonestr("{\"result\":\"coin added\"}"));
        else if ( retval == 0 )
            return(clonestr("{\"result\":\"coin already there\"}"));
        else return(clonestr("{\"error\":\"error adding coin\"}"));
    }
    return(clonestr("{\"result\":\"stub processed iguana json\"}"));
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
    printf("iguana_jsonstr.(%s)\n",retjsonstr);
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
    if ( (ptr= queue_dequeue(&coin->finishedQ,0)) != 0 )
    {
        if ( ptr->expired != 0 )
        {
            printf("garbage collection: expired.(%s)\n",ptr->jsonstr);
            myfree(ptr,ptr->allocsize);
        } else queue_enqueue("finishedQ",&coin->finishedQ,&ptr->DL,0);
    }
    if ( (ptr= queue_dequeue(&coin->jsonQ,0)) != 0 )
    {
        printf("process.(%s)\n",ptr->jsonstr);
        if ( (*ptr->retjsonstrp= iguana_jsonstr(coin,ptr->jsonstr)) == 0 )
            *ptr->retjsonstrp = clonestr("{\"error\":\"null return from iguana_jsonstr\"}");
        queue_enqueue("finishedQ",&coin->finishedQ,&ptr->DL,0);
        return(1);
    }
    return(0);
}

char *iguana_blockingjsonstr(struct iguana_info *coin,char *jsonstr,uint64_t tag,int32_t maxmillis)
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
                printf("blocking retjsonstr.(%s)\n",retjsonstr);
                queue_delete(&coin->finishedQ,&ptr->DL,allocsize,1);
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
    cJSON *json,*retjson; uint64_t tag; uint32_t timeout; int32_t retval;
    struct iguana_info *coin; char *method,*retjsonstr,*symbol,*retstr = 0;
    printf("iguana_JSON.(%s)\n",jsonstr);
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( (method= jstr(json,"method")) != 0 && strcmp(method,"addcoin") == 0 )
        {
            if ( (retval= iguana_launchcoin(jstr(json,"coin"),json)) > 0 )
                return(clonestr("{\"result\":\"launched coin\"}"));
            else if ( retval == 0 ) return(clonestr("{\"result\":\"coin already launched\"}"));
            else return(clonestr("{\"error\":\"error launching coin\"}"));
        }
        if ( (tag= j64bits(json,"tag")) == 0 )
            randombytes((uint8_t *)&tag,sizeof(tag));
        if ( (symbol= jstr(json,"coin")) != 0 )
        {
            if ( (coin= iguana_coin(symbol)) != 0 && coin->launched == 0 )
                iguana_launchcoin(symbol,json);
        }
        else coin = 0;
        if ( (timeout= juint(json,"timeout")) == 0 )
            timeout = IGUANA_JSONTIMEOUT;
        if ( (retjsonstr= iguana_blockingjsonstr(coin,jsonstr,tag,timeout)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retjsonstr)) == 0 )
            {
                printf("retjsonstr.(%s)\n",retjsonstr);
                retjson = cJSON_Parse("{\"error\":\"cant parse retjsonstr\"}");
            }
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
    free(retjsonstr);//,strlen(retjsonstr)+1);
    free(jsonstr);//,strlen(jsonstr)+1);
}

void iguana_main(void *arg)
{
    char helperstr[64],*helperargs,*coinargs=0,*secret,*jsonstr = arg;
    int32_t i,len,flag; cJSON *json; uint8_t secretbuf[512];
    //  portable_OS_init()?
    mycalloc(0,0,0);
    iguana_initQ(&helperQ,"helperQ");
    ensure_directory("DB");
    ensure_directory("tmp");
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
        IGUANA_NUMHELPERS = 4;
#else
        IGUANA_NUMHELPERS = 1;
#endif
    }
    for (i=0; i<IGUANA_NUMHELPERS; i++)
    {
        sprintf(helperstr,"{\"name\":\"helper.%d\"}",i);
        helperargs = clonestr(helperstr);
        iguana_launch(iguana_coin("BTCD"),"iguana_helper",iguana_helper,helperargs,IGUANA_PERMTHREAD);
    }
    if ( coinargs != 0 )
        iguana_launch(iguana_coin("BTCD"),"iguana_coins",iguana_coins,coinargs,IGUANA_PERMTHREAD);
    else
    {
#ifdef __APPLE__
        sleep(1);
        iguana_JSON("{\"agent\":\"iguana\",\"method\":\"addcoin\",\"maxpeers\":512,\"coin\":\"BTCD\",\"active\":1}");
#endif
    }
    if ( arg != 0 )
        iguana_JSON(arg);
    while ( 1 )
    {
        flag = 0;
        for (i=0; i<sizeof(Coins)/sizeof(*Coins); i++)
            if ( Coins[i] != 0 && Coins[i]->symbol[0] != 0 )
                flag += iguana_processjsonQ(Coins[i]);
        if ( flag == 0 )
            usleep(100000);
    }
}
