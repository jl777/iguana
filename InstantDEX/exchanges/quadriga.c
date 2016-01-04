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

#define EXCHANGE_NAME "quadriga"
#define UPDATE prices777_ ## quadriga
#define SUPPORTS quadriga ## _supports
#define SIGNPOST quadriga ## _signpost
#define TRADE quadriga ## _trade
#define ORDERSTATUS quadriga ## _orderstatus
#define CANCELORDER quadriga ## _cancelorder
#define OPENORDERS quadriga ## _openorders
#define TRADEHISTORY quadriga ## _tradehistory
#define BALANCES quadriga ## _balances
#define PARSEBALANCE quadriga ## _parsebalance
#define WITHDRAW quadriga ## _withdraw
#define CHECKBALANCE quadriga ## _checkbalance

double UPDATE(struct prices777 *prices,int32_t maxdepth)
{
    if ( prices->url[0] == 0 )
        sprintf(prices->url,"https://api.quadrigacx.com/v2/order_book?book=%s_%s",prices->lbase,prices->lrel);
    return(prices777_standard("quadriga",prices->url,prices,0,0,maxdepth,0));
}

int32_t SUPPORTS(char *base,char *rel)
{
    char *baserels[][2] = { {"btc","usd"}, {"btc","cad"} };
    return(baserel_polarity(baserels,(int32_t)(sizeof(baserels)/sizeof(*baserels)),base,rel));
}

cJSON *SIGNPOST(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *payload,char *path)
{
    char url[1024],req[1024],md5secret[128],tmp[1024],dest[1025],hdr1[512],hdr2[512],hdr3[512],hdr4[512],*sig,*data = 0;
    cJSON *json; uint64_t nonce;
    hdr1[0] = hdr2[0] = hdr3[0] = hdr4[0] = 0;
    json = 0;
    nonce = exchange_nonce(exchange) * 1000 + ((uint64_t)milliseconds() % 1000);
    sprintf(tmp,"%llu%s%s",(long long)nonce,exchange->userid,exchange->apikey);
    calc_md5(md5secret,exchange->apisecret,(int32_t)strlen(exchange->apisecret));
    if ( (sig= hmac_sha256_str(dest,md5secret,(int32_t)strlen(md5secret),tmp)) != 0 )
    {
        sprintf(req,"{\"key\":\"%s\",%s\"nonce\":%llu,\"signature\":\"%s\"}",exchange->apikey,payload,(long long)nonce,sig);
        sprintf(hdr1,"Content-Type:application/json");
        sprintf(hdr2,"charset=utf-8");
        sprintf(hdr3,"Content-Length:%ld",(long)strlen(req));
        sprintf(url,"https://api.quadrigacx.com/v2/%s",path);
        if ( dotrade == 0 )
            data = exchange_would_submit(req,hdr1,hdr2,hdr3,hdr4);
        else if ( (data= curl_post(cHandlep,url,0,req,hdr1,hdr2,hdr3,hdr4)) != 0 )
            json = cJSON_Parse(data);
    }
    if ( retstrp != 0 )
        *retstrp = data;
    else if ( data != 0 )
        free(data);
    return(json);
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr)
{
    //[{"btc_available":"0.00000000","btc_reserved":"0.00000000","btc_balance":"0.00000000","cad_available":"0.00","cad_reserved":"0.00","cad_balance":"0.00","usd_available":"0.00","usd_reserved":"0.00","usd_balance":"0.00","xau_available":"0.000000","xau_reserved":"0.000000","xau_balance":"0.000000","fee":"0.5000"}]
    char field[128],*str,*itemstr = 0; cJSON *obj; double reserv,total;
    *balancep = 0.;
    strcpy(field,coinstr);
    tolowercase(field);
    strcat(field,"_available");
    if ( exchange->balancejson != 0 && (str= jstr(exchange->balancejson,field)) != 0 )
    {
        *balancep = jdouble(exchange->balancejson,field);
        strcpy(field,coinstr), tolowercase(field), strcat(field,"_reserved");
        reserv = jdouble(exchange->balancejson,field);
        strcpy(field,coinstr), tolowercase(field), strcat(field,"_balance");
        total = jdouble(exchange->balancejson,field);
        obj = cJSON_CreateObject();
        jaddnum(obj,"balance",*balancep);
        jaddnum(obj,"locked_balance",reserv);
        jaddnum(obj,"total",total);
        itemstr = jprint(obj,1);
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

cJSON *BALANCES(void **cHandlep,struct exchange_info *exchange)
{
    return(SIGNPOST(cHandlep,1,0,exchange,"","balance"));
}

#include "checkbalance.c"

uint64_t TRADE(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume)
{
    char payload[1024],pairstr[64],*extra,*path; cJSON *json; uint64_t txid = 0;
    if ( (extra= *retstrp) != 0 )
        *retstrp = 0;
    if ( (dir= flipstr_for_exchange(exchange,pairstr,"%s_%s",dir,&price,&volume,base,rel)) == 0 )
    {
        printf("cant find baserel (%s/%s)\n",base,rel);
        return(0);
    }
    path = (dir > 0) ? "buy" : "sell";
    //key - API key
    //signature - signature
    //nonce - nonce
    //amount - amount of major currency
    //price - price to buy at
    //book - optional, if not specified, will default to btc_cad
    sprintf(payload,"\"amount\":%.6f,\"price\":%.3f,\"book\":\"%s_%s\",",volume,price,base,rel);
    if ( CHECKBALANCE(retstrp,dotrade,exchange,dir,base,rel,price,volume) == 0 && (json= SIGNPOST(cHandlep,dotrade,retstrp,exchange,payload,path)) != 0 )
    {
        // parse json and set txid
        free_json(json);
    }
    return(txid);
}

char *ORDERSTATUS(void **cHandlep,struct exchange_info *exchange,cJSON *argjson,uint64_t quoteid)
{
    char buf[64];
    sprintf(buf,"\"id\":%llu,",(long long)quoteid);
    return(jprint(SIGNPOST(cHandlep,1,0,exchange,buf,"lookup_order"),1));
}

char *CANCELORDER(void **cHandlep,struct exchange_info *exchange,cJSON *argjson,uint64_t quoteid)
{
    char buf[64];
    sprintf(buf,"\"id\":%llu,",(long long)quoteid);
    return(jprint(SIGNPOST(cHandlep,1,0,exchange,buf,"cancel_order"),1));
}

char *OPENORDERS(void **cHandlep,struct exchange_info *exchange,cJSON *argjson)
{
    return(jprint(SIGNPOST(cHandlep,1,0,exchange,"","open_orders"),1));
}

char *TRADEHISTORY(void **cHandlep,struct exchange_info *exchange,cJSON *argjson)
{
    return(jprint(SIGNPOST(cHandlep,1,0,exchange,"","user_transactions"),1));
}

char *WITHDRAW(void **cHandlep,struct exchange_info *exchange,cJSON *argjson)
{
    char buf[1024],*base,*destaddr; double amount;
    if ( (base= jstr(argjson,"base")) == 0 || strcmp(base,"BTC") != 0 )
        return(clonestr("{\"error\":\"base not specified or base != BTC\"}"));
    if ( (destaddr= jstr(argjson,"destaddr")) == 0 )
        return(clonestr("{\"error\":\"destaddr not specified\"}"));
    if ( (amount= jdouble(argjson,"amount")) < SMALLVAL )
        return(clonestr("{\"error\":\"amount not specified\"}"));
    sprintf(buf,"\"amount\":%.4f,\"address\":\"%s\",",amount,destaddr);
    printf("submit.(%s)\n",buf);
    return(jprint(SIGNPOST(cHandlep,1,0,exchange,"","bitcoin_withdrawal"),1));
}

struct exchange_funcs quadriga_funcs = EXCHANGE_FUNCS(quadriga,EXCHANGE_NAME);

#undef UPDATE
#undef SUPPORTS
#undef SIGNPOST
#undef TRADE
#undef ORDERSTATUS
#undef CANCELORDER
#undef OPENORDERS
#undef TRADEHISTORY
#undef BALANCES
#undef PARSEBALANCE
#undef WITHDRAW
#undef EXCHANGE_NAME
#undef CHECKBALANCE

