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

#include "includes/cJSON.h"

char Default_coin[64] = { "BTCD" };
char Default_agent[64] = { "ALL" };
#define IGUANA_FORMS "[ \
{\"newline\":0,\"disp\":\"select coin\",\"agent\":\"iguana\",\"method\":\"setcoin\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":10,\"rows\":1}]}, \
\
{\"disp\":\"simple explorer\",\"agent\":\"ramchain\",\"method\":\"explore\",\"fields\":[{\"skip\":1,\"field\":\"search\",\"cols\":65,\"rows\":1}]}, \
{\"disp\":\"block height\",\"agent\":\"ramchain\",\"method\":\"block\",\"fields\":[{\"field\":\"height\",\"cols\":10,\"rows\":1}]}, \
{\"disp\":\"block hash\",\"agent\":\"ramchain\",\"method\":\"block\",\"fields\":[{\"field\":\"hash\",\"cols\":65,\"rows\":1}]}, \
{\"disp\":\"txid\",\"agent\":\"ramchain\",\"method\":\"txid\",\"fields\":[{\"skip\":1,\"field\":\"hash\",\"cols\":65,\"rows\":1}]}, \
\
{\"disp\":\"addcoin\",\"agent\":\"iguana\",\"method\":\"addcoin\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":16,\"rows\":1}]}, \
{\"disp\":\"pausecoin\",\"agent\":\"iguana\",\"method\":\"pausecoin\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":16,\"rows\":1}]}, \
{\"disp\":\"startcoin\",\"agent\":\"iguana\",\"method\":\"startcoin\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":16,\"rows\":1}]}, \
{\"disp\":\"addnode\",\"agent\":\"iguana\",\"method\":\"addnode\",\"fields\":[{\"skip\":1,\"field\":\"ipaddr\",\"cols\":32,\"rows\":1}]}, \
{\"disp\":\"maxpeers\",\"agent\":\"iguana\",\"method\":\"maxpeers\",\"fields\":[{\"skip\":1,\"field\":\"max\",\"cols\":8,\"rows\":1}]}, \
{\"disp\":\"peers\",\"agent\":\"iguana\",\"method\":\"peers\",\"fields\":[{\"field\":\"coin\",\"cols\":16,\"rows\":1}]}, \
{\"disp\":\"nodestatus\",\"agent\":\"iguana\",\"method\":\"nodestatus\",\"fields\":[{\"skip\":1,\"field\":\"ipaddr\",\"cols\":32,\"rows\":1}]}, \
\
{\"disp\":\"rates\",\"agent\":\"PAX\",\"method\":\"rates\",\"fields\":[{\"skip\":1,\"field\":\"peg\",\"cols\":16,\"rows\":1}]},\
{\"disp\":\"prices\",\"agent\":\"PAX\",\"method\":\"prices\",\"fields\":[{\"skip\":1,\"field\":\"peg\",\"cols\":16,\"rows\":1}]},\
{\"agent\":\"PAX\",\"method\":\"lock\",\"fields\":[{\"skip\":1,\"field\":\"peg\",\"cols\":16,\"rows\":1},{\"skip\":1,\"field\":\"lockdays\",\"cols\":6,\"rows\":1},{\"skip\":1,\"field\":\"units\",\"cols\":12,\"rows\":1}]}, \
{\"agent\":\"PAX\",\"method\":\"redeem\",\"fields\":[{\"skip\":1,\"field\":\"txid\",\"cols\":65,\"rows\":1},{\"skip\":1,\"field\":\"dest\",\"cols\":65,\"rows\":1}]},\
{\"disp\":\"balance\",\"agent\":\"PAX\",\"method\":\"balance\",\"fields\":[{\"skip\":1,\"field\":\"address\",\"cols\":44,\"rows\":1}]},\
{\"agent\":\"PAX\",\"method\":\"rollover\",\"fields\":[{\"skip\":1,\"field\":\"txid\",\"cols\":16,\"rows\":1},{\"skip\":1,\"field\":\"newpeg\",\"cols\":16,\"rows\":1},{\"skip\":1,\"field\":\"newlockdays\",\"cols\":6,\"rows\":1}]},\
{\"agent\":\"PAX\",\"method\":\"swap\",\"fields\":[{\"skip\":1,\"field\":\"txid\",\"cols\":16,\"rows\":1},{\"skip\":1,\"field\":\"othertxid\",\"cols\":16,\"rows\":1}]},\
{\"agent\":\"PAX\",\"method\":\"bet\",\"fields\":[{\"skip\":1,\"field\":\"peg\",\"cols\":16,\"rows\":1},{\"skip\":1,\"field\":\"price\",\"cols\":16,\"rows\":1},{\"skip\":1,\"field\":\"amount\",\"cols\":16,\"rows\":1}]},\
\
{\"agent\":\"InstantDEX\",\"method\":\"placebid\",\"fields\":[{\"skip\":1,\"field\":\"base\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"rel\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"exchange\",\"cols\":16,\"rows\":1},{\"field\":\"price\",\"cols\":16,\"rows\":1},{\"field\":\"volume\",\"cols\":16,\"rows\":1}]}, \
{\"agent\":\"InstantDEX\",\"method\":\"placeask\",\"fields\":[{\"skip\":1,\"field\":\"base\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"rel\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"exchange\",\"cols\":16,\"rows\":1},{\"field\":\"price\",\"cols\":16,\"rows\":1},{\"field\":\"volume\",\"cols\":16,\"rows\":1}]}, \
{\"agent\":\"InstantDEX\",\"method\":\"orderbook\",\"fields\":[{\"skip\":1,\"field\":\"base\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"rel\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"exchange\",\"cols\":16,\"rows\":1}]}, \
{\"disp\":\"orderstatus\",\"agent\":\"InstantDEX\",\"method\":\"orderstatus\",\"fields\":[{\"skip\":1,\"field\":\"orderid\",\"cols\":32,\"rows\":1}]}, \
{\"disp\":\"cancelorder\",\"agent\":\"InstantDEX\",\"method\":\"cancelorder\",\"fields\":[{\"skip\":1,\"field\":\"orderid\",\"cols\":32,\"rows\":1}]}, \
{\"disp\":\"balance\",\"agent\":\"InstantDEX\",\"method\":\"balance\",\"fields\":[{\"skip\":1,\"field\":\"exchange\",\"cols\":16,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"allorderbooks\",\"agent\":\"InstantDEX\",\"method\":\"allorderbooks\",\"fields\":[{\"skip\":1,\"field\":\"allorderbooks\",\"cols\":1,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"openorders\",\"agent\":\"InstantDEX\",\"method\":\"openorders\",\"fields\":[{\"skip\":1,\"field\":\"openorders\",\"cols\":1,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"tradehistory\",\"agent\":\"InstantDEX\",\"method\":\"tradehistory\",\"fields\":[{\"skip\":1,\"field\":\"tradehistory\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"allexchanges\",\"agent\":\"InstantDEX\",\"method\":\"allexchanges\",\"fields\":[{\"skip\":1,\"field\":\"allexchanges\",\"cols\":1,\"rows\":1}]}, \
\
{\"agent\":\"pangea\",\"method\":\"bet\",\"fields\":[{\"skip\":1,\"field\":\"tableid\",\"cols\":24,\"rows\":1},{\"skip\":1,\"field\":\"amount\",\"cols\":24,\"rows\":1}]}, \
{\"disp\":\"call\",\"agent\":\"pangea\",\"method\":\"call\",\"fields\":[{\"skip\":1,\"field\":\"tableid\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"fold\",\"agent\":\"pangea\",\"method\":\"fold\",\"fields\":[{\"skip\":1,\"field\":\"tableid\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"status\",\"agent\":\"pangea\",\"method\":\"status\",\"fields\":[{\"skip\":1,\"field\":\"tableid\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"hand history\",\"agent\":\"pangea\",\"method\":\"handhistory\",\"fields\":[{\"skip\":1,\"field\":\"tableid\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"history\",\"agent\":\"pangea\",\"method\":\"history\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"follow\",\"agent\":\"pangea\",\"method\":\"follow\",\"fields\":[{\"skip\":1,\"field\":\"tableid\",\"cols\":24,\"rows\":1}]}, \
{\"disp\":\"lobby\",\"agent\":\"pangea\",\"method\":\"lobby\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":8,\"rows\":1}]}, \
{\"disp\":\"join\",\"agent\":\"pangea\",\"method\":\"join\",\"fields\":[{\"skip\":1,\"field\":\"tableid\",\"cols\":24,\"rows\":1}]}, \
{\"agent\":\"pangea\",\"method\":\"buyin\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"tableid\",\"cols\":24,\"rows\":1},{\"skip\":1,\"field\":\"amount\",\"cols\":12,\"rows\":1}]}, \
{\"agent\":\"pangea\",\"method\":\"newtournament\",\"fields\":[{\"field\":\"mintables\",\"cols\":8,\"rows\":1},{\"field\":\"maxtables\",\"cols\":4,\"rows\":1},{\"field\":\"starttime\",\"cols\":16,\"rows\":1},{\"field\":\"prizefund\",\"cols\":12,\"rows\":1},{\"field\":\"coin\",\"cols\":12,\"rows\":1}]}, \
{\"agent\":\"pangea\",\"method\":\"newtable\",\"fields\":[{\"field\":\"minplayers\",\"cols\":4,\"rows\":1},{\"field\":\"maxplayers\",\"cols\":4,\"rows\":1},{\"field\":\"rake\",\"cols\":4,\"rows\":1},{\"field\":\"bigblind\",\"cols\":12,\"rows\":1},{\"field\":\"ante\",\"cols\":12,\"rows\":1},{\"field\":\"minbuyin\",\"cols\":12,\"rows\":1},{\"field\":\"maxbuyin\",\"cols\":12,\"rows\":1}]}, \
{\"disp\":\"leave\",\"agent\":\"pangea\",\"method\":\"leave\",\"fields\":[{\"skip\":1,\"field\":\"tableid\",\"cols\":8,\"rows\":1}]}, \
\
{\"agent\":\"jumblr\",\"method\":\"send\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"amount\",\"cols\":13,\"rows\":1},{\"skip\":1,\"field\":\"address\",\"cols\":8,\"rows\":1}]}, \
{\"agent\":\"jumblr\",\"method\":\"invoice\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"amount\",\"cols\":13,\"rows\":1},{\"skip\":1,\"field\":\"address\",\"cols\":8,\"rows\":1}]}, \
{\"agent\":\"jumblr\",\"method\":\"shuffle\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"amount\",\"cols\":13,\"rows\":1}]}, \
{\"agent\":\"jumblr\",\"method\":\"balance\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"address\",\"cols\":13,\"rows\":1}]}, \
\
{\"newline\":0,\"disp\":\"InstantDEX\",\"agent\":\"iguana\",\"method\":\"setagent\",\"fields\":[{\"field\":\"InstantDEX\",\"cols\":1,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"PAX\",\"agent\":\"iguana\",\"method\":\"setagent\",\"fields\":[{\"field\":\"PAX\",\"cols\":1,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"pangea\",\"agent\":\"iguana\",\"method\":\"setagent\",\"fields\":[{\"field\":\"pangea\",\"cols\":1,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"jumblr\",\"agent\":\"iguana\",\"method\":\"setagent\",\"fields\":[{\"field\":\"jumblr\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"ramchain\",\"agent\":\"iguana\",\"method\":\"setagent\",\"fields\":[{\"field\":\"ramchain\",\"cols\":1,\"rows\":1}]} \
]"

char *HTMLheader =
"<!DOCTYPE HTML> \
<html style=\"overflow-y:scroll;-webkit-user-select: text\"> \
<head> \
<meta http-equiv=\"Pragma\" content=\"no-cache\"> \
<meta http-equiv=\"Expires\" content=\"-1\"> \
<title>iguana</title> \
<script src=\"jquery-2.1.4.min.js\" type=\"text/javascript\"></script> \
<link rel=\"stylesheet\" href=\"css/bootstrap.css\" type=\"text/css\"> \
\
</head> \
<body data-custom-load=\"true\" data-name=\"iguana\" data-tools=\"pnacl newlib glibc clang-newlib mac\" data-configs=\"Debug Release\" data-path=\"{tc}/{config}\">";

// <a href="./iguana/link?field=val">Link</a>

char *HTMLfooter =
"<script type=\"text/javascript\" src=\"js/util.js\"></script> \
\
<script type=\"text/javascript\" src=\"common.js\"></script> \
<script type=\"text/javascript\" src=\"example.js\"></script> \
\
<script src=\"js/bootstrap.js\" type=\"text/javascript\"></script> \
<script src=\"js/api.js\" type=\"text/javascript\" charset=\"utf-8\"></script> \
<script src=\"js/methods.js\" type=\"text/javascript\" charset=\"utf-8\"></script> \
<script src=\"js/sites.js\" type=\"text/javascript\" charset=\"utf-8\"></script> \
<script src=\"js/settings.js\" type=\"text/javascript\" charset=\"utf-8\"></script> \
<script src=\"js/jay.min.js\"></script> \
<script src=\"js/jay.ext.js\"></script> \
\
</body> \
</html>";

#define HTML_EMIT(str)  if ( (str) != 0 && (str)[0] != 0 ) strcpy(&retbuf[size],str), size += (int32_t)strlen(str)
char Prevjsonstr[1024],Currentjsonstr[1024];

char *iguana_rpc(char *agent,cJSON *json,char *data,int32_t datalen)
{
    //printf("agent.(%s) json.(%s) data[%d] %s\n",agent,jprint(json,0),datalen,data!=0?data:"");
    if ( data == 0 )
        return(iguana_JSON(jprint(json,0)));
    else return(iguana_JSON(data));
}

void iguana_urldecode(char *str)
{
    int32_t a,b,c; char *dest = str;
    while ( (c= *str) != 0 )
    {
        if ( c == '%' && (a= str[1]) != 0 && (b= str[2]) != 0 )
            *dest++ = (unhex(a)<<4) | unhex(b);
        else *dest++ = c;
    }
    *dest = 0;
}

char *iguana_parsebidask(char *base,char *rel,char *exchange,double *pricep,double *volumep,char *line)
{
    int32_t i;
    for (i=0; i<16&&line[i]!='/'&&line[i]!=0; i++)
        base[i] = line[i];
    base[i] = 0;
    touppercase(base);
    line += (i + 1);
    for (i=0; i<16&&line[i]!='/'&&line[i]!=0; i++)
        rel[i] = line[i];
    rel[i] = 0;
    touppercase(rel);
    line += (i + 1);
    for (i=0; i<16&&line[i]!='/'&&line[i]!=0; i++)
        exchange[i] = line[i];
    exchange[i] = 0;
    line += (i + 1);
    if ( strncmp(line,"price/",strlen("price/")) == 0 )
    {
        line += strlen("price/");
        *pricep = atof(line);
        if ( (line= strstr(line,"volume/")) != 0 )
        {
            line += strlen("volume/");
            *volumep = atof(line);
            for (i=0; i<16&&line[i]!=0; i++)
                if ( line[i] == '/' )
                {
                    i++;
                    break;
                }
            return(line+i);
        }
    }
    return(0);
}

char *iguana_InstantDEX(char *path,char *method)
{
    char *str,base[64],rel[64],exchange[64]; double price,volume;
    if ( (str= iguana_parsebidask(base,rel,exchange,&price,&volume,path)) != 0 )
    {
        if ( price > 0. && volume > 0. )
        {
            sprintf(Currentjsonstr,"{\"agent\":\"InstantDEX\",\"method\":\"%s\",\"base\":\"%s\",\"rel\":\"%s\",\"exchange\":\"%s\",\"price\":\%0.8f,\"volume\":%0.8f}",method,base,rel,exchange,price,volume);
            return(clonestr(Currentjsonstr));
        }
        else return(clonestr("{\"error\":\"invalid price and or volume\"}"));
    }
    return(clonestr("{\"error\":\"invalid price and or volume\"}"));
}

char *iguana_htmlget(char *path)
{
    char *iguana_coinjson(struct iguana_info *coin,char *method,cJSON *json);
    char *ramchain_parser(struct iguana_agent *agent,struct iguana_info *coin,char *method,cJSON *json);
    struct iguana_info *coin = 0; cJSON *json; bits256 hash2; int32_t height,i;
    char buf[64],retbuf[512],*retstr;
    for (i=0; path[i]!=0; i++)
        if ( path[i] == ' ' )
            break;
    path[i] = 0;
    if ( path[strlen(path)-1] == '/' )
        path[strlen(path)-1] = 0;
    //printf("GETCHECK.(%s)\n",path);
    if ( strncmp(path,"/ramchain/",strlen("/ramchain/")) == 0 )
    {
        path += strlen("/ramchain/");
        if ( strncmp(path,"block/",strlen("block/")) == 0 )
        {
            path += strlen("block/");
            if ( strncmp(path,"height/",strlen("height/")) == 0 )
            {
                height = atoi(path + strlen("height/"));
                sprintf(Currentjsonstr,"{\"agent\":\"ramchain\",\"method\":\"block\",\"coin\":\"%s\",\"height\":%d,\"txids\":1}",Default_coin,height);
                return(ramchain_parser(0,0,"block",cJSON_Parse(Currentjsonstr)));
            }
            else if ( strncmp(path,"hash/",strlen("hash/")) == 0 )
            {
                decode_hex(hash2.bytes,sizeof(hash2),path + strlen("hash/"));
                char str[65]; printf("ramchain blockhash.%s\n",bits256_str(str,hash2));
                sprintf(Currentjsonstr,"{\"agent\":\"ramchain\",\"method\":\"block\",\"coin\":\"%s\",\"hash\":\"%s\",\"txids\":1}",Default_coin,str);
                return(ramchain_parser(0,0,"block",cJSON_Parse(Currentjsonstr)));
            }
        }
        else if ( strncmp(path,"txid/",strlen("txid/")) == 0 )
        {
            decode_hex(hash2.bytes,sizeof(hash2),path + strlen("txid/"));
            char str[65]; printf("ramchain txid.%s\n",bits256_str(str,hash2));
            sprintf(Currentjsonstr,"{\"agent\":\"ramchain\",\"method\":\"tx\",\"coin\":\"%s\",\"txid\":\"%s\"}",Default_coin,str);
            return(ramchain_parser(0,0,"tx",cJSON_Parse(Currentjsonstr)));
        }
        else if ( strncmp(path,"explore/",strlen("explore/")) == 0 )
        {
            path += strlen("explore/");
            if ( Default_coin[0] != 0 )
            {
                coin = iguana_coin(Default_coin);
                sprintf(Currentjsonstr,"{\"agent\":\"iguana\",\"method\":\"explore\",\"coin\":\"%s\",\"search\":\"%s\"}",Default_coin,path);
            } else sprintf(Currentjsonstr,"{\"agent\":\"iguana\",\"method\":\"explore\",\"search\":\"%s\"}",path);
            json = cJSON_Parse(Currentjsonstr);
            retstr = ramchain_parser(0,0,"explore",json);
            free_json(json);
            return(retstr);
        }
        return(clonestr("{\"error\":\"ramchain unknown request\"}"));
    }
    else if ( strncmp(path,"/iguana/",strlen("/iguana/")) == 0 )
    {
        strcpy(Currentjsonstr,path);
        path += strlen("/iguana/");
        if ( strncmp(path,"setagent/",strlen("setagent/")) == 0 )
        {
            path += strlen("setagent/");
            if ( strncmp(path,"ramchain",strlen("ramchain")) == 0 || strncmp(path,"iguana",strlen("iguana")) == 0 || strncmp(path,"InstantDEX",strlen("InstantDEX")) == 0 || strncmp(path,"pangea",strlen("pangea")) == 0 || strncmp(path,"PAX",strlen("PAX")) == 0 || strncmp(path,"ALL",strlen("ALL")) == 0 || strncmp(path,"jumblr",strlen("jumblr")) == 0 )
            {
                if ( strncmp(Default_agent,path,strlen(path)) == 0 )
                {
                    strcpy(Default_agent,"ALL");
                    return(clonestr("{\"result\":\"ALL agents selected\"}"));
                }
                strcpy(Default_agent,path);
                if ( Default_agent[strlen(Default_agent)-1] == '/' )
                    Default_agent[strlen(Default_agent)-1] = 0;
                sprintf(buf,"{\"result\":\"agent selected\",\"name\":\"%s\"}",path);
                return(clonestr(buf));
            }
            return(clonestr("{\"error\":\"invalid agent specified\"}"));
        }
        else if ( strncmp(path,"setcoin/",strlen("setcoin/")) == 0 )
        {
            path += strlen("setcoin/");
            for (i=0; i<8&&path[i]!=0&&path[i]!=' '; i++)
                buf[i] = path[i];
            buf[i] = 0;
            touppercase(buf);
            for (i=0; i<64; i++)
            {
                if ( Coins[i] == 0 || Coins[i]->symbol[0] == 0 )
                    continue;
                printf("coin.(%s)\n",Coins[i]->symbol);
                if ( strcmp(Coins[i]->symbol,buf) == 0 )
                {
                    if ( strcmp(Default_coin,buf) != 0 )
                    {
                        strcpy(Default_coin,buf);
                        return(clonestr("{\"result\":\"changed default coin\"}"));
                    }
                    else return(clonestr("{\"result\":\"coin already default\"}"));
                }
            }
            sprintf(retbuf,"{\"result\":\"coin not found\",\"coin\":\"%s\"}",buf);
            return(clonestr(retbuf));
        }
        else
        {
            if ( strncmp(path,"peers/",strlen("peers/")) == 0 )
            {
                path += strlen("peers/");
                if ( Default_coin[0] != 0 )
                {
                    coin= iguana_coin(Default_coin);
                    sprintf(Currentjsonstr,"{\"agent\":\"iguana\",\"method\":\"peers\",\"coin\":\"%s\"}",Default_coin);
                } else sprintf(Currentjsonstr,"{\"agent\":\"iguana\",\"method\":\"peers\"}");
                json = cJSON_Parse(Currentjsonstr);
                retstr = iguana_coinjson(coin,"peers",json);
                free_json(json);
                return(retstr);
            }
            else if ( Default_coin[0] != 0 && (coin= iguana_coin(Default_coin)) != 0 )
            {
                if ( strncmp(path,"addnode/",strlen("addnode/")) == 0 )
                {
                    path += strlen("addnode/");
                    sprintf(Currentjsonstr,"{\"agent\":\"iguana\",\"method\":\"addnode\",\"coin\":\"%s\",\"ipaddr\":\"%s\"}",Default_coin,path);
                    json = cJSON_Parse(Currentjsonstr);
                    retstr = iguana_coinjson(coin,"addnode",json);
                    free_json(json);
                    return(retstr);
                }
                else if ( strncmp(path,"nodestatus/",strlen("nodestatus/")) == 0 )
                {
                    path += strlen("nodestatus/");
                    sprintf(Currentjsonstr,"{\"agent\":\"iguana\",\"method\":\"nodestatus\",\"coin\":\"%s\",\"ipaddr\":\"%s\"}",Default_coin,path);
                    json = cJSON_Parse(Currentjsonstr);
                    retstr = iguana_coinjson(coin,"nodestatus",json);
                    free_json(json);
                    return(retstr);
                }
                else if ( strncmp(path,"addcoin/",strlen("addcoin/")) == 0 )
                {
                    path += strlen("addcoin/");
                    for (i=0; i<8&&path[i]!=0&&path[i]!=' '; i++)
                        buf[i] = path[i];
                    buf[i] = 0;
                    touppercase(buf);
                    sprintf(Currentjsonstr,"{\"agent\":\"iguana\",\"method\":\"addcoin\",\"coin\":\"%s\"}",path);
                    json = cJSON_Parse(Currentjsonstr);
                    retstr = iguana_coinjson(coin,"addcoin",json);
                    free_json(json);
                    return(retstr);
                }
                else if ( strncmp(path,"startcoin/",strlen("startcoin/")) == 0 )
                {
                    path += strlen("startcoin/");
                    for (i=0; i<8&&path[i]!=0&&path[i]!=' '; i++)
                        buf[i] = path[i];
                    buf[i] = 0;
                    touppercase(buf);
                    sprintf(Currentjsonstr,"{\"agent\":\"iguana\",\"method\":\"startcoin\",\"coin\":\"%s\"}",path);
                    json = cJSON_Parse(Currentjsonstr);
                    retstr = iguana_coinjson(coin,"startcoin",json);
                    free_json(json);
                    return(retstr);
                }
                else if ( strncmp(path,"pausecoin/",strlen("pausecoin/")) == 0 )
                {
                    path += strlen("pausecoin/");
                    for (i=0; i<8&&path[i]!=0&&path[i]!=' '; i++)
                        buf[i] = path[i];
                    buf[i] = 0;
                    touppercase(buf);
                    sprintf(Currentjsonstr,"{\"agent\":\"iguana\",\"method\":\"pausecoin\",\"coin\":\"%s\"}",path);
                    json = cJSON_Parse(Currentjsonstr);
                    retstr = iguana_coinjson(coin,"pausecoin",json);
                    free_json(json);
                    return(retstr);
                }
                else if ( strncmp(path,"maxpeers/",strlen("maxpeers/")) == 0 )
                {
                    path += strlen("maxpeers/");
                    sprintf(Currentjsonstr,"{\"agent\":\"iguana\",\"method\":\"maxpeers\",\"coin\":\"%s\",\"max\":%d}",Default_coin,atoi(path));
                    json = cJSON_Parse(Currentjsonstr);
                    retstr = iguana_coinjson(coin,"maxpeers",json);
                    free_json(json);
                    return(retstr);
                }
               return(clonestr("{\"result\":\"iguana method not found\"}"));
            }
            return(clonestr("{\"result\":\"iguana method needs coin\"}"));
        }
    }
    else if ( strncmp(path,"/InstantDEX/",strlen("/InstantDEX/")) == 0 )
    {
        double price,volume; char base[16],rel[16],exchange[16];
        path += strlen("/InstantDEX/");
        if ( strncmp(path,"placebid/",strlen("placebid/")) == 0 )
        {
            path += strlen("placebid/");
            return(iguana_InstantDEX(path,"placebid"));
        }
        else if ( strncmp(path,"placeask/",strlen("placeask/")) == 0 )
        {
            path += strlen("placeask/");
            return(iguana_InstantDEX(path,"placeask"));
        }
        else if ( strncmp(path,"orderbook/",strlen("orderbook/")) == 0 )
        {
            path += strlen("orderbook/");
            iguana_parsebidask(base,rel,exchange,&price,&volume,path);
            sprintf(Currentjsonstr,"{\"agent\":\"InstantDEX\",\"method\":\"orderbook\",\"base\":\"%s\",\"rel\":\"%s\",\"exchange\":\"%s\"}",base,rel,exchange);
            return(clonestr(Currentjsonstr));
        }
        else if ( strncmp(path,"orderstatus/",strlen("orderstatus/")) == 0 )
        {
            path += strlen("orderstatus/");
            sprintf(Currentjsonstr,"{\"agent\":\"InstantDEX\",\"method\":\"orderstatus\",\"orderid\":\"%s\"}",path);
            return(clonestr(Currentjsonstr));
        }
        else if ( strncmp(path,"cancelorder/",strlen("cancelorder/")) == 0 )
        {
            path += strlen("cancelorder/");
            sprintf(Currentjsonstr,"{\"agent\":\"InstantDEX\",\"method\":\"cancelorder\",\"orderid\":\"%s\"}",path);
            return(clonestr(Currentjsonstr));
        }
        else if ( strncmp(path,"balance/",strlen("balance/")) == 0 )
        {
            path += strlen("balance/");
            iguana_parsebidask(base,rel,exchange,&price,&volume,path);
            if ( path[0] != ' ' && path[0] != '/' )
                sprintf(Currentjsonstr,"{\"agent\":\"InstantDEX\",\"method\":\"balance\",\"exchange\":\"%s\"}",path);
            else sprintf(Currentjsonstr,"{\"agent\":\"InstantDEX\",\"method\":\"balance\"}");
            return(clonestr(Currentjsonstr));
        }
        else if ( strncmp(path,"openorders/",strlen("openorders/")) == 0 )
        {
            path += strlen("openorders/");
            sprintf(Currentjsonstr,"{\"agent\":\"InstantDEX\",\"method\":\"openorders\"}");
            return(clonestr(Currentjsonstr));
        }
        else if ( strncmp(path,"tradehistory/",strlen("tradehistory/")) == 0 )
        {
            path += strlen("tradehistory/");
            sprintf(Currentjsonstr,"{\"agent\":\"InstantDEX\",\"method\":\"tradehistory\"}");
            return(clonestr(Currentjsonstr));
        }
        else if ( strncmp(path,"allorderbooks/",strlen("allorderbooks/")) == 0 )
        {
            path += strlen("allorderbooks/");
            sprintf(Currentjsonstr,"{\"agent\":\"InstantDEX\",\"method\":\"allorderbooks\"}");
            return(clonestr(Currentjsonstr));
        }
        else if ( strncmp(path,"allexchanges/",strlen("allexchanges/")) == 0 )
        {
            path += strlen("allexchanges/");
            sprintf(Currentjsonstr,"{\"agent\":\"InstantDEX\",\"method\":\"allexchanges\"}");
            return(clonestr(Currentjsonstr));
        }
    }
    else if ( strncmp(path,"/pangea/",strlen("/pangea/")) == 0 )
    {
        path += strlen("/pangea/");
    }
    else if ( strncmp(path,"/jumblr/",strlen("/jumblr/")) == 0 )
    {
        path += strlen("/jumblr/");
    }
    else printf("no match to (%s)\n",path);
    return(0);
}

char *iguana_rpcparse(int32_t *postflagp,char *jsonstr)
{
    cJSON *json = 0; int32_t i,n,datalen,postflag = 0;
    char *key,*reststr,*str,*retstr,*data = 0,*value,*agent = "SuperNET";
    //printf("rpcparse.(%s)\n",jsonstr);
    *postflagp = 0;
    if ( strncmp("POST",jsonstr,4) == 0 )
        jsonstr += 6, *postflagp = postflag = 1;
    else if ( strncmp("GET",jsonstr,3) == 0 )
    {
        jsonstr += 4;
        str = 0;
        if ( (str= iguana_htmlget(jsonstr)) == 0 && (reststr= strstr(jsonstr,"Referer: http://127.0.0.1:7778")) != 0 )
        {
            reststr += strlen("Referer: http://127.0.0.1:7778");
            str = iguana_htmlget(reststr);
        }
        if ( str != 0 )
        {
            json = cJSON_CreateObject();
            jaddstr(json,"result",str);
            str = cJSON_Print(json);
            free_json(json);
            return(str);
        }
        jsonstr++;
    }
    else return(0);
    n = (int32_t)strlen(jsonstr);
    for (i=0; i<n; i++)
        if ( jsonstr[i] == '?' )
            break;
    if ( i == n )
    {
        //printf("no url\n");
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
                    //printf("post.(%s) (%c)\n",data,data[0]);
                    //iguana_urldecode(data);
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

int32_t iguana_htmlgen(char *retbuf,int32_t bufsize,char *result,char *error,cJSON *json,char *tabname,char *origjsonstr)
{
    char *url = "http://127.0.0.1:7778";
    int i,j,m,size = 0,n,rows,cols; cJSON *array,*obj,*array2,*item,*tmp;
    char formheader[512],formfooter[512],clickname[512],buf[512],fieldbuf[512],fieldindex[2],postjson[8192];
    char *disp,*fieldname,*button,*agent,*method,*str;
    bufsize--;
    HTML_EMIT("<html> <head></head> <body> <text>");
    HTML_EMIT("Selected coin: <b>"); HTML_EMIT(Default_coin);
    sprintf(formfooter,"\t<input type=\"button\" value=\"%s\" onclick=\"click_%s()\" /></form>","InstantDEX","iguana47_setagent"); HTML_EMIT(formfooter);
    sprintf(formfooter,"\t<input type=\"button\" value=\"%s\" onclick=\"click_%s()\" /></form>","PAX","iguana48_setagent"); HTML_EMIT(formfooter);
    sprintf(formfooter,"\t<input type=\"button\" value=\"%s\" onclick=\"click_%s()\" /></form>","pangea","iguana49_setagent"); HTML_EMIT(formfooter);
    sprintf(formfooter,"\t<input type=\"button\" value=\"%s\" onclick=\"click_%s()\" /></form>","jumblr","iguana50_setagent"); HTML_EMIT(formfooter);
    sprintf(formfooter,"\t<input type=\"button\" value=\"%s\" onclick=\"click_%s()\" /></form>","ramchain","iguana51_setagent"); HTML_EMIT(formfooter);
    HTML_EMIT("   Agent:    "); HTML_EMIT(Default_agent);

    HTML_EMIT("<br><br/>");
    HTML_EMIT(origjsonstr); HTML_EMIT(" -> ");
    HTML_EMIT("<textarea cols=\"150\" rows=\"10\"  name=\"jsonresult\"/>");
    tmp = cJSON_Parse(result), str = cJSON_Print(tmp), free_json(tmp);
    HTML_EMIT(str); free(str);
    HTML_EMIT(error);
    HTML_EMIT("</textarea><br><br/>");
    formheader[0] = formfooter[0] = 0;
    if ( (array= jarray(&n,json,"forms")) != 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            //printf("FORM[%d] of %d %s\n",i,n,jprint(item,0));
            // {"forms":[{"name":"block","agent":"ramchain","fields":[{"disp":"height of block","field":"height","cols":10,"rows":1},{"disp":"blockhash","field":"hash","cols":65,"rows":1}]}]}
            if ( (method= jstr(item,"method")) == 0 )
                method = "missing";
            sprintf(clickname,"%s%d_%s",tabname,i,method);
            if ( (button= jstr(item,"button")) == 0 )
                button = method;
            if ( (agent= jstr(item,"agent")) == 0 )
                agent = "iguana";
            if ( strncmp(Default_agent,"ALL",3) != 0 && strcmp(method,"setagent") != 0 && strcmp(method,"setcoin") != 0 && strncmp(Default_agent,agent,strlen(agent)) != 0 )
            {
                //printf("Default_agent.%s vs agent.(%s)\n",Default_agent,agent);
                continue;
            }
            sprintf(buf,"<script> function click_%s()\n{\n",clickname);
            HTML_EMIT(buf);
            sprintf(postjson,"%s/%s",agent,method);
            //printf("form.%s button.%s [%s]\n",formname,button,postjson);
            if ( (array2= jarray(&m,item,"fields")) != 0 )
            {
                for (j=0; j<m; j++)
                {
                    obj = jitem(array2,j);
                    //printf("item[%d] -> (%s)\n",j,jprint(obj,0));
                    sprintf(fieldindex,"%c",'A'+j);
                    if ( (fieldname= jstr(obj,"field")) != 0 )
                    {
                        sprintf(buf,"%s = document.%s.%s.value;\n",fieldindex,clickname,fieldname);
                        HTML_EMIT(buf);
                        //sprintf(postjson+strlen(postjson),",\"%s\":\"' + %s + '\"",fieldname,fieldindex);
                        if ( juint(obj,"skip") == 0 )
                            sprintf(postjson+strlen(postjson),"/%s/' + %s + '",fieldname,fieldindex);
                        else sprintf(postjson+strlen(postjson),"/' + %s + '",fieldindex);
                    }
                }
                //strcat(postjson,"}");
                sprintf(&retbuf[size],"location.href = '%s/%s';\n}</script>\r\n",url,postjson), size += strlen(&retbuf[size]);
                sprintf(formheader,"<form name=\"%s\" action=\"%s\" method=\"POST\" onsubmit=\"return submitForm(this);\"><table>",clickname,url);
                HTML_EMIT(formheader);
                disp = jstr(item,"disp");
                for (j=0; j<m; j++)
                {
                    obj = jitem(array2,j);
                    rows = juint(obj,"rows");
                    cols = juint(obj,"cols");
                    if ( (fieldname= jstr(obj,"field")) == 0 )
                        sprintf(fieldbuf,"%s_%c",clickname,'A'+j), fieldname = fieldbuf;
                    if ( rows == 0 && cols == 0 )
                        sprintf(buf,"<input type=\"text\" name=\"%s\"/>",fieldname);
                    else sprintf(buf,"<textarea cols=\"%d\" rows=\"%d\"  name=\"%s\"/ %s></textarea>",cols,rows,fieldname,cols == 1 ? "hidden" : "");
                    str = disp==0?jstr(obj,"disp"):disp;
                    sprintf(&retbuf[size],"<td>%s</td> <td> %s </td>\r\n",str!=0?str:fieldname,buf), size += strlen(&retbuf[size]);
                }
                sprintf(formfooter,"<td colspan=\"2\"> <input type=\"button\" value=\"%s\" onclick=\"click_%s()\" /></td> </tr>\n</table></form>",button,clickname);
                HTML_EMIT(formfooter);
            }
        }
    }
    HTML_EMIT("<br><br/>"); HTML_EMIT("</body></html>"); HTML_EMIT("<br><br/>");
    return((int32_t)strlen(retbuf));
}
#undef HTML_EMIT

char *iguana_htmlresponse(char *retbuf,int32_t bufsize,int32_t *remainsp,int32_t localaccess,char *retstr,int32_t freeflag)
{
    static char *html = "<html> <head></head> <body> %s </body> </html>";
    char *result=0,*error=0; int32_t n; cJSON *json,*formsjson;
    retbuf[0] = 0;
    /*if ( localaccess == 0 )
     sprintf(retbuf+strlen(retbuf),"Access-Control-Allow-Origin: *\r\n");
     else sprintf(retbuf+strlen(retbuf),"Access-Control-Allow-Origin: null\r\n");
     sprintf(retbuf+strlen(retbuf),"Access-Control-Allow-Credentials: true\r\n");
     sprintf(retbuf+strlen(retbuf),"Access-Control-Allow-Headers: Authorization, Content-Type\r\n");
     sprintf(retbuf+strlen(retbuf),"Access-Control-Allow-Methods: GET, POST\r\n");
     sprintf(retbuf+strlen(retbuf),"Cache-Control: no-cache, no-store, must-revalidate\r\n");
     sprintf(retbuf+strlen(retbuf),"Content-type: text/html\r\n");
     sprintf(retbuf+strlen(retbuf),"Content-Length: %d\r\n\r\n",n);*/
    sprintf(retbuf+strlen(retbuf),"<!DOCTYPE HTML>\n\r");
    n = (int32_t)strlen(retbuf);
    formsjson = cJSON_Parse(IGUANA_FORMS);
    if ( (json= cJSON_Parse(retstr)) == 0 )
        json = cJSON_CreateObject();
    jadd(json,"forms",formsjson);
    error = jstr(json,"error");
    result = jstr(json,"result");
    //printf("process.(%s)\n",jprint(formsjson,0));
    n = iguana_htmlgen(&retbuf[n],bufsize-n,result,error,json,"iguana",Currentjsonstr);
    free_json(json);
    if ( n == 0 )
    {
        n = (int32_t)(strlen(html) + strlen(retstr) + 1);
        sprintf(retbuf+strlen(retbuf),html,retstr);
    }
    if ( freeflag != 0 )
        free(retstr);
    if ( n > bufsize )
    {
        printf("htmlresponse overflowed buffer[%d] with %d\n",bufsize,n);
        exit(-1);
    }
    *remainsp = n;
    return(retbuf);
}

void iguana_rpcloop(void *args)
{
    int32_t recvlen,bindsock,postflag,sock,remains,numsent,len; socklen_t clilen;
    char ipaddr[64],jsonbuf[8192],*buf,*retstr,*space;//,*retbuf; ,n,i,m
    struct sockaddr_in cli_addr; uint32_t ipbits,i,size = 1024*1024; uint16_t port;
    port = IGUANA_RPCPORT;//coin->chain->portrpc;
    bindsock = iguana_socket(1,"127.0.0.1",port);
    printf("iguana_rpcloop 127.0.0.1:%d bind sock.%d\n",port,bindsock);
    space = calloc(1,size);
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
                retstr = iguana_rpcparse(&postflag,jsonbuf);
                break;
            }
        }
        if ( retstr != 0 )
        {
            i = 0;
            if ( postflag == 0 )
                retstr = iguana_htmlresponse(space,size,&remains,1,retstr,1);
            else remains = (int32_t)strlen(retstr);
            //printf("RETBUF.(%s)\n",retstr);
            while ( remains > 0 )
            {
                if ( (numsent= (int32_t)send(sock,&retstr[i],remains,MSG_NOSIGNAL)) < 0 )
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
                    i += numsent;
                    if ( remains > 0 )
                        printf("iguana sent.%d remains.%d of len.%d\n",numsent,remains,recvlen);
                }
            }
            //free(retstr);
        }
        if ( Currentjsonstr[0] != 0 )
            strcpy(Prevjsonstr,Currentjsonstr);
        Currentjsonstr[0] = 0;
        //printf("done response sock.%d\n",sock);
        close(sock);
    }
}