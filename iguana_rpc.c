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

#include <curl/curl.h>
#include <curl/easy.h>

// return data from the server
struct return_string {
    char *ptr;
    size_t len;
};

size_t accumulate(void *ptr, size_t size, size_t nmemb, struct return_string *s);
void init_string(struct return_string *s);


/************************************************************************
 *
 * return the current system time in milliseconds
 *
 ************************************************************************/

#define EXTRACT_BITCOIND_RESULT     // if defined, ensures error is null and returns the "result" field
#ifdef EXTRACT_BITCOIND_RESULT

/************************************************************************
 *
 * perform post processing of the results
 *
 ************************************************************************/

char *post_process_bitcoind_RPC(char *debugstr,char *command,char *rpcstr,char *params)
{
    long i,j,len;
    char *retstr = 0;
    cJSON *json,*result,*error;
    if ( command == 0 || rpcstr == 0 || rpcstr[0] == 0 )
    {
        printf("<<<<<<<<<<< bitcoind_RPC: %s post_process_bitcoind_RPC.%s.[%s]\n",debugstr,command,rpcstr);
        return(rpcstr);
    }
    json = cJSON_Parse(rpcstr);
    if ( json == 0 )
    {
        printf("<<<<<<<<<<< bitcoind_RPC: %s post_process_bitcoind_RPC.%s can't parse.(%s) params.(%s)\n",debugstr,command,rpcstr,params);
        free(rpcstr);
        return(0);
    }
    result = cJSON_GetObjectItem(json,"result");
    error = cJSON_GetObjectItem(json,"error");
    if ( error != 0 && result != 0 )
    {
        if ( (error->type&0xff) == cJSON_NULL && (result->type&0xff) != cJSON_NULL )
        {
            retstr = cJSON_Print(result);
            len = strlen(retstr);
            if ( retstr[0] == '"' && retstr[len-1] == '"' )
            {
                for (i=1,j=0; i<len-1; i++,j++)
                    retstr[j] = retstr[i];
                retstr[j] = 0;
            }
        }
        else if ( (error->type&0xff) != cJSON_NULL || (result->type&0xff) != cJSON_NULL )
            printf("<<<<<<<<<<< bitcoind_RPC: %s post_process_bitcoind_RPC (%s) error.%s\n",debugstr,command,rpcstr);
        free(rpcstr);
    } else retstr = rpcstr;
    free_json(json);
    //fprintf(stderr,"<<<<<<<<<<< bitcoind_RPC: postprocess returns.(%s)\n",retstr);
    return(retstr);
}
#endif

/************************************************************************
 *
 * perform the query
 *
 ************************************************************************/

char *Jay_NXTrequest(char *command,char *params)
{
    char *retstr = 0;
    // issue JS Jay request
    // wait till it is done
    return(retstr);
}

char *bitcoind_RPC(char **retstrp,char *debugstr,char *url,char *userpass,char *command,char *params)
{
    static int count,count2; static double elapsedsum,elapsedsum2; extern int32_t USE_JAY;
    struct curl_slist *headers = NULL; struct return_string s; CURLcode res; CURL *curl_handle;
    char *bracket0,*bracket1,*databuf = 0; long len; int32_t specialcase,numretries; double starttime;
    if ( USE_JAY != 0 && (strncmp(url,"http://127.0.0.1:7876/nxt",strlen("http://127.0.0.1:7876/nxt")) == 0 || strncmp(url,"https://127.0.0.1:7876/nxt",strlen("https://127.0.0.1:7876/nxt")) == 0) )
    {
        if ( (databuf= Jay_NXTrequest(command,params)) != 0 )
            return(databuf);
    }
    numretries = 0;
    if ( debugstr != 0 && strcmp(debugstr,"BTCD") == 0 && command != 0 && strcmp(command,"SuperNET") ==  0 )
        specialcase = 1;
    else specialcase = 0;
    if ( url[0] == 0 )
        strcpy(url,"http://127.0.0.1:7876/nxt");
    if ( specialcase != 0 && 0 )
        printf("<<<<<<<<<<< bitcoind_RPC: debug.(%s) url.(%s) command.(%s) params.(%s)\n",debugstr,url,command,params);
try_again:
    if ( retstrp != 0 )
        *retstrp = 0;
    starttime = milliseconds();
    curl_handle = curl_easy_init();
    init_string(&s);
    headers = curl_slist_append(0,"Expect:");
    
  	curl_easy_setopt(curl_handle,CURLOPT_USERAGENT,"mozilla/4.0");//"Mozilla/4.0 (compatible; )");
    curl_easy_setopt(curl_handle,CURLOPT_HTTPHEADER,	headers);
    curl_easy_setopt(curl_handle,CURLOPT_URL,		url);
    curl_easy_setopt(curl_handle,CURLOPT_WRITEFUNCTION,	(void *)accumulate); 		// send all data to this function
    curl_easy_setopt(curl_handle,CURLOPT_WRITEDATA,		&s); 			// we pass our 's' struct to the callback
    curl_easy_setopt(curl_handle,CURLOPT_NOSIGNAL,		1L);   			// supposed to fix "Alarm clock" and long jump crash
	curl_easy_setopt(curl_handle,CURLOPT_NOPROGRESS,	1L);			// no progress callback
    if ( strncmp(url,"https",5) == 0 )
    {
        curl_easy_setopt(curl_handle,CURLOPT_SSL_VERIFYPEER,0);
        curl_easy_setopt(curl_handle,CURLOPT_SSL_VERIFYHOST,0);
    }
    if ( userpass != 0 )
        curl_easy_setopt(curl_handle,CURLOPT_USERPWD,	userpass);
    databuf = 0;
    if ( params != 0 )
    {
        if ( command != 0 && specialcase == 0 )
        {
            len = strlen(params);
            if ( len > 0 && params[0] == '[' && params[len-1] == ']' ) {
                bracket0 = bracket1 = (char *)"";
            }
            else
            {
                bracket0 = (char *)"[";
                bracket1 = (char *)"]";
            }
            
            databuf = (char *)malloc(256 + strlen(command) + strlen(params));
            sprintf(databuf,"{\"id\":\"jl777\",\"method\":\"%s\",\"params\":%s%s%s}",command,bracket0,params,bracket1);
            //printf("url.(%s) userpass.(%s) databuf.(%s)\n",url,userpass,databuf);
            //
        } //else if ( specialcase != 0 ) fprintf(stderr,"databuf.(%s)\n",params);
        curl_easy_setopt(curl_handle,CURLOPT_POST,1L);
        if ( databuf != 0 )
            curl_easy_setopt(curl_handle,CURLOPT_POSTFIELDS,databuf);
        else curl_easy_setopt(curl_handle,CURLOPT_POSTFIELDS,params);
    }
    //laststart = milliseconds();
    res = curl_easy_perform(curl_handle);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl_handle);
    if ( databuf != 0 ) // clean up temporary buffer
    {
        free(databuf);
        databuf = 0;
    }
    if ( res != CURLE_OK )
    {
        numretries++;
        if ( specialcase != 0 )
        {
            printf("<<<<<<<<<<< bitcoind_RPC.(%s): BTCD.%s timeout params.(%s) s.ptr.(%s) err.%d\n",url,command,params,s.ptr,res);
            free(s.ptr);
            return(0);
        }
        else if ( numretries >= 2 )
        {
            printf("Maximum number of retries exceeded!\n");
            free(s.ptr);
            return(0);
        }
        printf( "curl_easy_perform() failed: %s %s.(%s %s), retries: %d\n",curl_easy_strerror(res),debugstr,url,command,numretries);
        free(s.ptr);
        sleep((1<<numretries));
        goto try_again;
        
    }
    else
    {
        if ( command != 0 && specialcase == 0 )
        {
            count++;
            elapsedsum += (milliseconds() - starttime);
            if ( (count % 10000) == 0)
                printf("%d: ave %9.6f | elapsed %.3f millis | bitcoind_RPC.(%s) url.(%s)\n",count,elapsedsum/count,(milliseconds() - starttime),command,url);
            if ( retstrp != 0 )
            {
                *retstrp = s.ptr;
                return(s.ptr);
            }
            return(post_process_bitcoind_RPC(debugstr,command,s.ptr,params));
        }
        else
        {
            if ( 0 && specialcase != 0 )
                fprintf(stderr,"<<<<<<<<<<< bitcoind_RPC: BTCD.(%s) -> (%s)\n",params,s.ptr);
            count2++;
            elapsedsum2 += (milliseconds() - starttime);
            if ( (count2 % 10000) == 0)
                printf("%d: ave %9.6f | elapsed %.3f millis | NXT calls.(%s) cmd.(%s)\n",count2,elapsedsum2/count2,(double)(milliseconds() - starttime),url,command);
            return(s.ptr);
        }
    }
    printf("bitcoind_RPC: impossible case\n");
    free(s.ptr);
    return(0);
}



/************************************************************************
 *
 * Initialize the string handler so that it is thread safe
 *
 ************************************************************************/

void init_string(struct return_string *s)
{
    s->len = 0;
    s->ptr = (char *)calloc(1,s->len+1);
    if ( s->ptr == NULL )
    {
        fprintf(stderr,"init_string malloc() failed\n");
        exit(-1);
    }
    s->ptr[0] = '\0';
}

/************************************************************************
 *
 * Use the "writer" to accumulate text until done
 *
 ************************************************************************/

size_t accumulate(void *ptr,size_t size,size_t nmemb,struct return_string *s)
{
    size_t new_len = s->len + size*nmemb;
    s->ptr = (char *)realloc(s->ptr,new_len+1);
    if ( s->ptr == NULL )
    {
        fprintf(stderr, "accumulate realloc() failed\n");
        exit(-1);
    }
    memcpy(s->ptr+s->len,ptr,size*nmemb);
    s->ptr[new_len] = '\0';
    s->len = new_len;
    return(size * nmemb);
}

struct MemoryStruct { char *memory; size_t size; };

static size_t WriteMemoryCallback(void *ptr,size_t size,size_t nmemb,void *data)
{
    size_t realsize = (size * nmemb);
    struct MemoryStruct *mem = (struct MemoryStruct *)data;
    mem->memory = (ptr != 0) ? realloc(mem->memory,mem->size + realsize + 1) : malloc(mem->size + realsize + 1);
    if ( mem->memory != 0 )
    {
        if ( ptr != 0 )
            memcpy(&(mem->memory[mem->size]),ptr,realsize);
        mem->size += realsize;
        mem->memory[mem->size] = 0;
    }
    return(realsize);
}

void *curl_post(CURL **cHandlep,char *url,char *userpass,char *postfields,char *hdr0,char *hdr1,char *hdr2,char *hdr3)
{
    struct MemoryStruct chunk; CURL *cHandle; long code; struct curl_slist *headers = 0;
    if ( (cHandle= *cHandlep) == NULL )
		*cHandlep = cHandle = curl_easy_init();
    else curl_easy_reset(cHandle);
    //#ifdef DEBUG
	//curl_easy_setopt(cHandle,CURLOPT_VERBOSE, 1);
    //#endif
	curl_easy_setopt(cHandle,CURLOPT_USERAGENT,"mozilla/4.0");//"Mozilla/4.0 (compatible; )");
	curl_easy_setopt(cHandle,CURLOPT_SSL_VERIFYPEER,0);
	//curl_easy_setopt(cHandle,CURLOPT_SSLVERSION,1);
	curl_easy_setopt(cHandle,CURLOPT_URL,url);
  	curl_easy_setopt(cHandle,CURLOPT_CONNECTTIMEOUT,10);
    if ( userpass != 0 && userpass[0] != 0 )
        curl_easy_setopt(cHandle,CURLOPT_USERPWD,userpass);
	if ( postfields != 0 && postfields[0] != 0 )
    {
        curl_easy_setopt(cHandle,CURLOPT_POST,1);
		curl_easy_setopt(cHandle,CURLOPT_POSTFIELDS,postfields);
    }
    if ( hdr0 != NULL && hdr0[0] != 0 )
    {
        //printf("HDR0.(%s) HDR1.(%s) HDR2.(%s) HDR3.(%s)\n",hdr0!=0?hdr0:"",hdr1!=0?hdr1:"",hdr2!=0?hdr2:"",hdr3!=0?hdr3:"");
        headers = curl_slist_append(headers,hdr0);
        if ( hdr1 != 0 && hdr1[0] != 0 )
            headers = curl_slist_append(headers,hdr1);
        if ( hdr2 != 0 && hdr2[0] != 0 )
            headers = curl_slist_append(headers,hdr2);
        if ( hdr3 != 0 && hdr3[0] != 0 )
            headers = curl_slist_append(headers,hdr3);
    } //headers = curl_slist_append(0,"Expect:");
    if ( headers != 0 )
        curl_easy_setopt(cHandle,CURLOPT_HTTPHEADER,headers);
    //res = curl_easy_perform(cHandle);
    memset(&chunk,0,sizeof(chunk));
    curl_easy_setopt(cHandle,CURLOPT_WRITEFUNCTION,WriteMemoryCallback);
    curl_easy_setopt(cHandle,CURLOPT_WRITEDATA,(void *)&chunk);
    curl_easy_perform(cHandle);
    curl_easy_getinfo(cHandle,CURLINFO_RESPONSE_CODE,&code);
    if ( code != 200 )
        printf("error: (%s) server responded with code %ld\n",url,code);
    if ( headers != 0 )
        curl_slist_free_all(headers);
    return(chunk.memory);
}

void curlhandle_free(void *curlhandle)
{
    curl_easy_cleanup(curlhandle);
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
/*    static int32_t testi,good,bad;
    char *retjsonstr,jsonstr[4096],checkstr[sizeof(jsonstr)]; // should be big enough
    //if ( (rand() % 1000) < 999 ) // if no test active, just return 0
        return(0);
    if ( iguana_rpctestvector(coin,checkstr,jsonstr,sizeof(jsonstr),testi++) > 0 )
    {
        retjsonstr = iguana_rpc(coin,jsonstr);
        if ( iguana_rpctestcheck(coin,jsonstr,retjsonstr) < 0 )
            bad++, printf("rpctestcheck.%s error: (%s) -> (%s) | good.%d bad.%d %.2f%%\n",coin->symbol,jsonstr,retjsonstr,good,bad,100.*(double)good/(good+bad));
        else good++;
        free(retjsonstr);
        return(1); // indicates was active
    }*/
    return(0);
}

char *pangea_parser(struct iguana_agent *agent,struct iguana_info *coin,char *method,cJSON *json)
{
    return(clonestr("{\"error\":\"pangea API is not yet\"}"));
}

char *InstantDEX_parser(struct iguana_agent *agent,struct iguana_info *coin,char *method,cJSON *json)
{
    return(clonestr("{\"error\":\"InstantDEX API is not yet\"}"));
}

char *jumblr_parser(struct iguana_agent *agent,struct iguana_info *coin,char *method,cJSON *json)
{
    return(clonestr("{\"error\":\"jumblr API is not yet\"}"));
}

struct iguana_txid *iguana_blocktx(struct iguana_info *coin,struct iguana_txid *tx,struct iguana_block *block,int32_t i)
{
    struct iguana_bundle *bp; uint32_t txidind;
    if ( i >= 0 && i < block->txn_count )
    {
        if ( block->height >= 0 && block->hdrsi == block->height/coin->chain->bundlesize && block->bundlei == (block->height % coin->chain->bundlesize) )
        {
            if ( (bp= coin->bundles[block->hdrsi]) != 0 )
            {
                if ( (txidind= bp->firsttxidinds[block->bundlei]) > 0 )
                {
                    if ( iguana_bundletx(coin,bp,block->bundlei,tx,txidind+i) == tx )
                        return(tx);
                    printf("error getting txidind.%d + i.%d from hdrsi.%d\n",txidind,i,block->hdrsi);
                    return(0);
                }
            }
        }
    }
    return(0);
}

struct iguana_txid *iguana_txidfind(struct iguana_info *coin,bits256 hash2)
{
    struct iguana_txid *tx = 0;
    return(tx);
}

cJSON *iguana_blockjson(struct iguana_info *coin,struct iguana_block *block,int32_t txidsflag)
{
    char str[65]; int32_t i; struct iguana_txid *tx,T; cJSON *array,*json = cJSON_CreateObject();
    jaddstr(json,"blockhash",bits256_str(str,block->hash2));
    jaddnum(json,"height",block->height);
    jaddstr(json,"merkle_root",bits256_str(str,block->merkle_root));
    jaddstr(json,"prev_block",bits256_str(str,block->prev_block));
    jaddnum(json,"timestamp",block->timestamp);
    jaddnum(json,"nonce",block->nonce);
    jaddnum(json,"nBits",block->bits);
    jaddnum(json,"version",block->version);
    jaddnum(json,"PoW",block->PoW);
    jaddnum(json,"numvouts",block->numvouts);
    jaddnum(json,"numvins",block->numvins);
    jaddnum(json,"ipbits",block->ipbits);
    jaddnum(json,"recvlen",block->recvlen);
    jaddnum(json,"hdrsi",block->hdrsi);
    jaddnum(json,"bundlei",block->bundlei);
    jaddnum(json,"mainchain",block->mainchain);
    jaddnum(json,"valid",block->valid);
    jaddnum(json,"txn_count",block->txn_count);
    if ( txidsflag != 0 )
    {
        array = cJSON_CreateArray();
        for (i=0; i<block->txn_count; i++)
        {
            if ( (tx= iguana_blocktx(coin,&T,block,i)) != 0 )
                jaddistr(array,bits256_str(str,tx->txid));
        }
        jadd(json,"txids",array);
    }
    return(json);
}

cJSON *iguana_voutjson(struct iguana_info *coin,struct iguana_msgvout *vout)
{
    static bits256 zero;
    char scriptstr[8192+1],coinaddr[65]; uint8_t rmd160[20],addrtype; cJSON *json = cJSON_CreateObject();
    jaddnum(json,"value",dstr(vout->value));
    if ( vout->pk_script != 0 && vout->pk_scriptlen*2+1 < sizeof(scriptstr) )
    {
        if ( iguana_calcrmd160(coin,rmd160,vout->pk_script,vout->pk_scriptlen,zero) > 0 )
            addrtype = coin->chain->p2shval;
        else addrtype = coin->chain->pubval;
        btc_convrmd160(coinaddr,addrtype,rmd160);
        jaddstr(json,"address",coinaddr);
        init_hexbytes_noT(scriptstr,vout->pk_script,vout->pk_scriptlen);
        jaddstr(json,"payscript",scriptstr);
    }
    return(json);
}

cJSON *iguana_vinjson(struct iguana_info *coin,struct iguana_msgvin *vin)
{
    char scriptstr[8192+1],str[65]; cJSON *json = cJSON_CreateObject();
    jaddstr(json,"prev_hash",bits256_str(str,vin->prev_hash));
    jaddnum(json,"prev_vout",vin->prev_vout);
    jaddnum(json,"sequence",vin->sequence);
    if ( vin->script != 0 && vin->scriptlen*2+1 < sizeof(scriptstr) )
    {
        init_hexbytes_noT(scriptstr,vin->script,vin->scriptlen);
        jaddstr(json,"sigscript",scriptstr);
    }
    return(json);
}

cJSON *iguana_txjson(struct iguana_info *coin,struct iguana_txid *tx)
{
    struct iguana_msgvin vin; struct iguana_msgvout vout; int32_t i; char str[65]; cJSON *vouts,*vins,*json;
    json = cJSON_CreateObject();
    jaddstr(json,"txid",bits256_str(str,tx->txid));
    jaddnum(json,"version",tx->version);
    jaddnum(json,"timestamp",tx->timestamp);
    jaddnum(json,"locktime",tx->locktime);
    vins = cJSON_CreateArray();
    vouts = cJSON_CreateArray();
    for (i=0; i<tx->numvouts; i++)
    {
        iguana_voutset(coin,&vout,tx,i);
        jaddi(vouts,iguana_voutjson(coin,&vout));
    }
    jadd(json,"vouts",vouts);
    for (i=0; i<tx->numvins; i++)
    {
        iguana_vinset(coin,&vin,tx,i);
        jaddi(vins,iguana_vinjson(coin,&vin));
    }
    jadd(json,"vins",vins);
    return(json);
}

char *ramchain_parser(struct iguana_agent *agent,struct iguana_info *coin,char *method,cJSON *json)
{
    char *symbol,*hashstr,*txidstr,*coinaddr,*txbytes,rmd160str[41]; int32_t height,i,n,valid = 0;
    cJSON *addrs,*retjson,*retitem; uint8_t rmd160[20],addrtype; bits256 hash2,checktxid;
    struct iguana_txid *tx,T; struct iguana_block *block = 0;
    /*{"agent":"ramchain","method":"block","coin":"BTCD","hash":"<sha256hash>"}
    {"agent":"ramchain","method":"block","coin":"BTCD","height":345600}
    {"agent":"ramchain","method":"tx","coin":"BTCD","txid":"<sha txid>"}
    {"agent":"ramchain","method":"rawtx","coin":"BTCD","txid":"<sha txid>"}
    {"agent":"ramchain","method":"balance","coin":"BTCD","address":"<coinaddress>"}
    {"agent":"ramchain","method":"balance","coin":"BTCD","addrs":["<coinaddress>",...]}
    {"agent":"ramchain","method":"totalreceived","coin":"BTCD","address":"<coinaddress>"}
    {"agent":"ramchain","method":"totalsent","coin":"BTCD","address":"<coinaddress>"}
    {"agent":"ramchain","method":"unconfirmed","coin":"BTCD","address":"<coinaddress>"}
    {"agent":"ramchain","method":"utxo","coin":"BTCD","address":"<coinaddress>"}
    {"agent":"ramchain","method":"utxo","coin":"BTCD","addrs":["<coinaddress0>", "<coinadress1>",...]}
    {"agent":"ramchain","method":"txs","coin":"BTCD","block":"<blockhash>"}
    {"agent":"ramchain","method":"txs","coin":"BTCD","height":12345}
    {"agent":"ramchain","method":"txs","coin":"BTCD","address":"<coinaddress>"}
    {"agent":"ramchain","method":"status","coin":"BTCD"}*/
    memset(&hash2,0,sizeof(hash2));
    if ( (symbol= jstr(json,"coin")) != 0 )
    {
        if ( coin == 0 )
            coin = iguana_coin(symbol);
        else if ( strcmp(symbol,coin->symbol) != 0 )
            return(clonestr("{\"error\":\"mismatched coin symbol\"}"));
    }
    if ( coin == 0 )
        return(clonestr("{\"error\":\"no coin specified\"}"));
    if ( (coinaddr= jstr(json,"address")) != 0 )
    {
        if ( btc_addr2univ(&addrtype,rmd160,coinaddr) == 0 )
        {
            if ( addrtype == coin->chain->pubval || addrtype == coin->chain->p2shval )
                valid = 1;
            else return(clonestr("{\"error\":\"invalid addrtype\"}"));
        } else return(clonestr("{\"error\":\"cant convert address to rmd160\"}"));
    }
    if ( strcmp(method,"block") == 0 )
    {
        if ( (hashstr= jstr(json,"hash")) != 0 && strlen(hashstr) == sizeof(bits256)*2 )
            decode_hex(hash2.bytes,sizeof(hash2),hashstr);
        else
        {
            height = juint(json,"height");
            hash2 = iguana_blockhash(coin,height);
        }
        retitem = cJSON_CreateObject();
        if ( (block= iguana_blockfind(coin,hash2)) != 0 )
            return(jprint(iguana_blockjson(coin,block,juint(json,"txids")),1));
        else return(clonestr("{\"error\":\"cant find block\"}"));
    }
    else if ( strcmp(method,"tx") == 0 )
    {
        if ( (txidstr= jstr(json,"txid")) != 0 && strlen(txidstr) == sizeof(bits256)*2 )
        {
            retitem = cJSON_CreateObject();
            decode_hex(hash2.bytes,sizeof(hash2),txidstr);
            if ( (tx= iguana_txidfind(coin,hash2)) != 0 )
            {
                jadd(retitem,"tx",iguana_txjson(coin,tx));
                return(jprint(retitem,1));
            }
            return(clonestr("{\"error\":\"cant find txid\"}"));
        }
        else return(clonestr("{\"error\":\"invalid txid\"}"));
    }
    else if ( strcmp(method,"rawtx") == 0 )
    {
        if ( (txidstr= jstr(json,"txid")) != 0 && strlen(txidstr) == sizeof(bits256)*2 )
        {
            decode_hex(hash2.bytes,sizeof(hash2),txidstr);
            if ( (tx= iguana_txidfind(coin,hash2)) != 0 )
            {
                if ( (txbytes= iguana_txbytes(coin,&checktxid,tx)) != 0 )
                {
                    retitem = cJSON_CreateObject();
                    jaddstr(retitem,"rawtx",txbytes);
                    myfree(txbytes,strlen(txbytes)+1);
                    return(jprint(retitem,1));
                } else return(clonestr("{\"error\":\"couldnt generate txbytes\"}"));
            }
            return(clonestr("{\"error\":\"cant find txid\"}"));
        }
        else return(clonestr("{\"error\":\"invalid txid\"}"));
    }
    else if ( strcmp(method,"txs") == 0 )
    {
        if ( (hashstr= jstr(json,"block")) != 0 && strlen(hashstr) == sizeof(bits256)*2 )
        {
            decode_hex(hash2.bytes,sizeof(hash2),hashstr);
            if ( (block= iguana_blockfind(coin,hash2)) == 0 )
                return(clonestr("{\"error\":\"cant find blockhash\"}"));
        }
        else if ( jobj(json,"height") != 0 )
        {
            height = juint(json,"height");
            hash2 = iguana_blockhash(coin,height);
            if ( (block= iguana_blockfind(coin,hash2)) == 0 )
                return(clonestr("{\"error\":\"cant find block at height\"}"));
        }
        else if ( valid == 0 )
            return(clonestr("{\"error\":\"txs needs blockhash or height or address\"}"));
        retitem = cJSON_CreateArray();
        if ( block != 0 )
        {
            for (i=0; i<block->txn_count; i++)
            {
                if ( (tx= iguana_blocktx(coin,&T,block,i)) != 0 )
                    jaddi(retitem,iguana_txjson(coin,tx));
            }
        }
        else
        {
            init_hexbytes_noT(rmd160str,rmd160,20);
            jaddnum(retitem,"addrtype",addrtype);
            jaddstr(retitem,"rmd160",rmd160str);
            jaddstr(retitem,"txlist","get list of all tx for this address");
        }
        return(jprint(retitem,1));
    }
    else if ( strcmp(method,"status") == 0 )
    {
        if ( coin != 0 )
        {
            retitem = cJSON_CreateObject();
            jaddstr(retitem,"status","coin status");
            return(jprint(retitem,1));
        }
        else return(clonestr("{\"error\":\"status needs coin\"}"));
    }
    else if ( coin != 0 )
    {
        n = 0;
        if ( valid == 0 )
        {
            if ( (addrs= jarray(&n,json,"addrs")) == 0 )
                return(clonestr("{\"error\":\"need address or addrs\"}"));
        }
        for (i=0; i<=n; i++)
        {
            retitem = cJSON_CreateObject();
            if ( i > 0 )
                retjson = cJSON_CreateArray();
            if ( i > 0 )
            {
                if ( (coinaddr= jstr(jitem(addrs,i-1),0)) == 0 )
                    return(clonestr("{\"error\":\"missing address in addrs\"}"));
                if ( btc_addr2univ(&addrtype,rmd160,coinaddr) < 0 )
                {
                    free_json(retjson);
                    return(clonestr("{\"error\":\"illegal address in addrs\"}"));
                }
                if ( addrtype != coin->chain->pubval && addrtype != coin->chain->p2shval )
                    return(clonestr("{\"error\":\"invalid addrtype in addrs\"}"));
            }
            if ( strcmp(method,"utxo") == 0 )
            {
                jaddstr(retitem,"utxo","utxo entry");
            }
            else if ( strcmp(method,"unconfirmed") == 0 )
            {
                jaddstr(retitem,"unconfirmed","unconfirmed entry");
            }
            else if ( strcmp(method,"balance") == 0 )
            {
                jaddstr(retitem,"balance","balance entry");
            }
            else if ( strcmp(method,"totalreceived") == 0 )
            {
                jaddstr(retitem,"totalreceived","totalreceived entry");
            }
            else if ( strcmp(method,"totalsent") == 0 )
            {
                jaddstr(retitem,"totalsent","totalsent entry");
            }
            if ( n == 0 )
                return(jprint(retitem,1));
            else jaddi(retjson,retitem);
        }
        return(jprint(retjson,1));
    }
    return(clonestr("{\"error\":\"illegal ramchain method or missing coin\"}"));
}

