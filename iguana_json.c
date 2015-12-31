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

char *iguana_rpc(char *agent,cJSON *json,char *data,int32_t datalen)
{
    //printf("agent.(%s) json.(%s) data[%d] %s\n",agent,jprint(json,0),datalen,data!=0?data:"");
    if ( data == 0 )
        return(iguana_JSON(jprint(json,0)));
    else return(iguana_JSON(data));
}

char *iguana_rpcparse(char *jsonstr)
{
    int32_t i,n,datalen,postflag = 0; char *key,*retstr,*data = 0,*value,*agent = "SuperNET"; cJSON *json = 0;
    if ( strncmp("POST",jsonstr,4) == 0 )
        jsonstr += 6, postflag = 1;
    else if ( strncmp("GET",jsonstr,3) == 0 )
        jsonstr += 5;
    else return(0);
    n = (int32_t)strlen(jsonstr);
    for (i=0; i<n; i++)
        if ( jsonstr[i] == '?' )
            break;
    if ( i == n )
    {
        printf("no url\n");
        return(0);
    }
    if ( i > 0 )
    {
        jsonstr[i] = 0;
        agent = jsonstr;
        jsonstr += i;
    }
    jsonstr++;
    json = cJSON_CreateObject();
    jaddstr(json,"agent",agent);
    while ( 1 )
    {
        n = (int32_t)strlen(jsonstr);
        key = jsonstr;
        value = 0;
        for (i=0; i<n; i++)
        {
            if ( jsonstr[i] == ' ' || jsonstr[i] == '&' )
                break;
            else if ( jsonstr[i] == '=' )
            {
                if ( value != 0 )
                {
                    printf("parse error.(%s)\n",jsonstr);
                    free_json(json);
                    return(0);
                }
                jsonstr[i] = 0;
                value = &jsonstr[++i];
            }
        }
        if ( value == 0 )
            value = "";
        jsonstr += i;
        if ( jsonstr[0] == ' ' )
        {
            jsonstr[0] = 0;
            jsonstr++;
            if ( key != 0 && key[0] != 0 )
                jaddstr(json,key,value);
            //printf("{%s:%s}\n",key,value);
            break;
        }
        jsonstr[0] = 0;
        jsonstr++;
        if ( key != 0 && key[0] != 0 )
            jaddstr(json,key,value);
        //printf("{%s:%s}\n",key,value);
        if ( i == 0 )
            break;
    }
    n = (int32_t)strlen(jsonstr);
    datalen = 0;
    if ( postflag != 0 )
    {
        for (i=0; i<n; i++)
        {
            //printf("(%d) ",jsonstr[i]);
            if ( jsonstr[i] == '\n' || jsonstr[i] == '\r' )
            {
                //printf("[%s] cmp.%d\n",jsonstr+i+1,strncmp(jsonstr+i+1,"Content-Length:",strlen("Content-Length:")));
                if ( strncmp(jsonstr+i+1,"Content-Length:",strlen("Content-Length:")) == 0 )
                {
                    datalen = (int32_t)atoi(jsonstr + i + 1 + strlen("Content-Length:") + 1);
                    data = &jsonstr[n - datalen];
                    //printf("post.(%s) len.%d (%c)\n",data,len,data[0]);
                }
            }
        }
    }
    retstr = iguana_rpc(agent,json,data,datalen);
    free_json(json);
    return(retstr);
    //printf("post.%d json.(%s) data[%d] %s\n",postflag,jprint(json,0),datalen,data!=0?data:"");
    //return(json);
}

void iguana_rpcloop(void *args)
{
    int32_t recvlen,bindsock,sock,remains,numsent,len; socklen_t clilen;
    char ipaddr[64],jsonbuf[8192],*buf,*retstr; struct sockaddr_in cli_addr; uint32_t ipbits; uint16_t port;
    port = IGUANA_RPCPORT;//coin->chain->portrpc;
    bindsock = iguana_socket(1,"127.0.0.1",port);
    printf("iguana_rpcloop 127.0.0.1:%d bind sock.%d\n",port,bindsock);
    while ( bindsock >= 0 )
    {
        clilen = sizeof(cli_addr);
        printf("ACCEPT (%s:%d) on sock.%d\n","127.0.0.1",port,bindsock);
        sock = accept(bindsock,(struct sockaddr *)&cli_addr,&clilen);
        if ( sock < 0 )
        {
            printf("ERROR on accept usock.%d\n",sock);
            continue;
        }
        memcpy(&ipbits,&cli_addr.sin_addr.s_addr,sizeof(ipbits));
        expand_ipbits(ipaddr,ipbits);
        //printf("RPC.%d for %x (%s)\n",sock,ipbits,ipaddr);
        //printf("%p got.(%s) from %s | usock.%d ready.%u dead.%u\n",addr,H.command,addr->ipaddr,addr->usock,addr->ready,addr->dead);
        memset(jsonbuf,0,sizeof(jsonbuf));
        remains = (int32_t)(sizeof(jsonbuf) - 1);
        buf = jsonbuf;
        recvlen = 0;
        retstr = 0;
        while ( remains > 0 )
        {
            if ( (len= (int32_t)recv(sock,buf,remains,0)) < 0 )
            {
                if ( errno == EAGAIN )
                {
                    printf("EAGAIN for len %d, remains.%d\n",len,remains);
                    usleep(10000);
                }
                break;
            }
            else
            {
                if ( len > 0 )
                {
                    remains -= len;
                    recvlen += len;
                    buf = &buf[len];
                } else usleep(10000);
                //printf("got.(%s) %d remains.%d of total.%d\n",jsonbuf,recvlen,remains,len);
                retstr = iguana_rpcparse(jsonbuf);
                break;
            }
        }
        if ( retstr != 0 )
        {
            //printf("jsonbuf.(%s)\n",jsonbuf);
            remains = (int32_t)strlen(retstr)+1;
            while ( remains > 0 )
            {
                if ( (numsent= (int32_t)send(sock,retstr,remains,MSG_NOSIGNAL)) < 0 )
                {
                    if ( errno != EAGAIN && errno != EWOULDBLOCK )
                    {
                        printf("%s: %s numsent.%d vs remains.%d len.%d errno.%d (%s) usock.%d\n",retstr,ipaddr,numsent,remains,recvlen,errno,strerror(errno),sock);
                        break;
                    }
                }
                else if ( remains > 0 )
                {
                    remains -= numsent;
                    if ( remains > 0 )
                        printf("iguana sent.%d remains.%d of len.%d\n",numsent,remains,recvlen);
                }
            }
            free(retstr);
        }
        //printf("done response sock.%d\n",sock);
        close(sock);
    }
}

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
                    //coin->myservices = atoi(Hardcoded_coins[i][2]);
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
    //printf("iguana_json(%s)\n",jprint(json,0));
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
        coin->active = 0;
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
    //printf("iguana_jsonstr.(%s)\n",jsonstr);
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
        //printf("process.(%s)\n",ptr->jsonstr);
        if ( (*ptr->retjsonstrp= iguana_jsonstr(coin,ptr->jsonstr)) == 0 )
            *ptr->retjsonstrp = clonestr("{\"error\":\"null return from iguana_jsonstr\"}");
        queue_enqueue("finishedQ",&coin->finishedQ,&ptr->DL,0);
        return(1);
    }
    return(0);
}

char *iguana_blockingjsonstr(struct iguana_info *coin,char *jsonstr,uint64_t tag,int32_t maxmillis)
{
    struct iguana_jsonitem *ptr; char *retjsonstr = 0; int32_t len,allocsize; double expiration = milliseconds() + maxmillis;
    if ( coin == 0 )
    {
        //printf("no coin case.(%s)\n",jsonstr);
        return(iguana_genericjsonstr(jsonstr));
    }
    else
    {
        //printf("blocking case.(%s)\n",jsonstr);
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
                //printf("blocking retjsonstr.(%s)\n",retjsonstr);
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
            printf("retjsonstr.(%s)\n",retjsonstr);
            if ( (retjson= cJSON_Parse(retjsonstr)) == 0 )
            {
                retjson = cJSON_Parse("{\"error\":\"cant parse retjsonstr\"}");
            }
            jdelete(retjson,"tag");
            jadd64bits(retjson,"tag",tag);
            retstr = jprint(retjson,1);
            printf("retstr.(%s) retjsonstr.%p retjson.%p\n",retstr,retjsonstr,retjson);
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
        if ( jobj(json,"numhelpers") != 0 )
            IGUANA_NUMHELPERS = juint(json,"numhelpers");
        if ( (secret= jstr(json,"secret")) != 0 )
        {
            len = (int32_t)strlen(secret);
            if ( is_hexstr(secret,0) != 0 && len <= (sizeof(secretbuf)<<1) )
            {
                len >>= 1;
                decode_hex(secretbuf,len,secret);
            } else vcalc_sha256(0,secretbuf,(void *)secret,len), len = sizeof(bits256);
        }
        if ( jobj(json,"coins") != 0 )
            coinargs = jsonstr;
    }
    if ( IGUANA_NUMHELPERS == 0 )
        IGUANA_NUMHELPERS = 1;
    for (i=0; i<IGUANA_NUMHELPERS; i++)
    {
        sprintf(helperstr,"{\"name\":\"helper.%d\"}",i);
        helperargs = clonestr(helperstr);
        iguana_launch(iguana_coin("BTCD"),"iguana_helper",iguana_helper,helperargs,IGUANA_PERMTHREAD);
    }
    iguana_launch(iguana_coin("BTCD"),"rpcloop",iguana_rpcloop,iguana_coin("BTCD"),IGUANA_PERMTHREAD);
    if ( coinargs != 0 )
        iguana_launch(iguana_coin("BTCD"),"iguana_coins",iguana_coins,coinargs,IGUANA_PERMTHREAD);
    else if ( 0 )
    {
#ifdef __APPLE__
        sleep(1);
        iguana_JSON("{\"agent\":\"iguana\",\"method\":\"addcoin\",\"services\":0,\"maxpeers\":2,\"coin\":\"BTCD\",\"active\":1}");
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
