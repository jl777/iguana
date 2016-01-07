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

// threadsafe
int32_t iguana_rwnum(int32_t rwflag,uint8_t *serialized,int32_t len,void *endianedp)
{
    int32_t i; uint64_t x;
    if ( rwflag == 0 )
    {
        x = 0;
        for (i=len-1; i>=0; i--)
        {
            x <<= 8;
            x |= serialized[i];
        }
        switch ( len )
        {
            case 1: *(uint8_t *)endianedp = (uint8_t)x; break;
            case 2: *(uint16_t *)endianedp = (uint16_t)x; break;
            case 4: *(uint32_t *)endianedp = (uint32_t)x; break;
            case 8: *(uint64_t *)endianedp = (uint64_t)x; break;
        }
    }
    else
    {
        x = 0;
        switch ( len )
        {
            case 1: x = *(uint8_t *)endianedp; break;
            case 2: x = *(uint16_t *)endianedp; break;
            case 4: x = *(uint32_t *)endianedp; break;
            case 8: x = *(uint64_t *)endianedp; break;
        }
        for (i=0; i<len; i++,x >>= 8)
            serialized[i] = (uint8_t)(x & 0xff);
    }
    return(len);
}

int32_t iguana_validatehdr(struct iguana_info *coin,struct iguana_msghdr *H)
{
    int32_t i,len; char *validcommands[] =
    {
        "version", "verack", "getaddr", "addr", "inv", "getdata", "notfound", "getblocks", "getheaders",
        "headers", "tx", "block", "mempool", "ping", "pong", "reject", "filterload", "filteradd", "filterclear", "merkleblock", "alert"
    };
    for (i=0; i<sizeof(validcommands)/sizeof(*validcommands); i++)
        if ( strcmp(H->command,validcommands[i]) == 0 )
        {
            iguana_rwnum(0,H->serdatalen,sizeof(H->serdatalen),(uint32_t *)&len);
            if ( len > IGUANA_MAXPACKETSIZE )
                return(-1);
            return(len);
        }
    return(-1);
}

int32_t iguana_rwbignum(int32_t rwflag,uint8_t *serialized,int32_t len,uint8_t *endianedp)
{
    int32_t i;
    if ( rwflag == 0 )
    {
        for (i=0; i<len; i++)
            endianedp[i] = serialized[len - 1 - i];
    }
    else
    {
        for (i=0; i<len; i++)
            serialized[i] = endianedp[len - 1 - i];
    }
    return(len);
}

int32_t iguana_sethdr(struct iguana_msghdr *H,const uint8_t netmagic[4],char *command,uint8_t *data,int32_t datalen)
{
    bits256 hash2,tmp; int32_t i;
    memset(H,0,sizeof(*H));
    memcpy(H->netmagic,netmagic,4);
    strncpy(H->command,command,12);
    iguana_rwnum(1,H->serdatalen,sizeof(int32_t),&datalen);
    if ( data != 0 && datalen != 0 )
    {
        hash2 = bits256_doublesha256(0,data,datalen);
        iguana_rwbignum(1,tmp.bytes,sizeof(tmp),hash2.bytes);
        for (i=0; i<4; i++)
            H->hash[i] = tmp.bytes[i];
    }
    else H->hash[0] = 0x5d, H->hash[1] = 0xf6, H->hash[2] = 0xe0, H->hash[3] = 0xe2;
    return(datalen + sizeof(*H));
}

uint8_t *iguana_varint16(int32_t rwflag,uint8_t *serialized,uint16_t *varint16p)
{
    uint16_t n = 0;
    if ( rwflag == 0 )
    {
        n = *serialized++;
        n |= ((int32_t)*serialized++ << 8);
        *varint16p = n;
    }
    else
    {
        n = *varint16p;
        *serialized++ = (uint8_t)n & 0xff;
        *serialized++ = (uint8_t)(n >> 8) & 0xff;
    }
    return(serialized);
}

uint8_t *iguana_varint32(int32_t rwflag,uint8_t *serialized,uint16_t *varint16p)
{
    serialized = iguana_varint16(rwflag,serialized,varint16p);
    serialized = iguana_varint16(rwflag,serialized,&varint16p[1]);
    return(serialized);
}

uint8_t *iguana_varint64(int32_t rwflag,uint8_t *serialized,uint32_t *varint32p)
{
    serialized = iguana_varint32(rwflag,serialized,(uint16_t *)varint32p);
    serialized = iguana_varint32(rwflag,serialized,(uint16_t *)&varint32p[1]);
    return(serialized);
}

int32_t iguana_rwvarint(int32_t rwflag,uint8_t *serialized,uint64_t *varint64p)
{
    uint64_t n; int32_t vlen = 1;
    if ( rwflag == 0 )
    {
        *varint64p = 0;
        if ( (n= *serialized++) >= 0xfd )
        {
            if ( n == 0xfd )
            {
                n = 0;
                iguana_varint16(rwflag,serialized,(uint16_t *)&n);
                vlen += 2;
            }
            else if ( n == 0xfe )
            {
                n = 0;
                iguana_varint32(rwflag,serialized,(uint16_t *)&n);
                vlen += 4;
            }
            else if ( n == 0xff )
            {
                n = 0;
                iguana_varint64(rwflag,serialized,(uint32_t *)&n);
                vlen += 8;
            }
        }
        *varint64p = n;
    }
    else
    {
        n = *varint64p;
        if ( n < 0xfd )
            *serialized++ = (uint8_t)n;
        else if ( n == 0xfd )
        {
            *serialized++ = 0xfd;
            iguana_varint16(rwflag,serialized,(uint16_t *)varint64p);
            vlen += 2;
        }
        else if ( n == 0xfe )
        {
            *serialized++ = 0xfe;
            iguana_varint32(rwflag,serialized,(uint16_t *)varint64p);
            vlen += 4;
        }
        else if ( n == 0xff )
        {
            *serialized++ = 0xff;
            iguana_varint64(rwflag,serialized,(uint32_t *)varint64p);
            vlen += 8;
        }
    }
    return(vlen);
}

int32_t iguana_rwvarint32(int32_t rwflag,uint8_t *serialized,uint32_t *int32p)
{
    int32_t len; uint64_t x = 0;
    if ( rwflag != 0 )
        x = *int32p;
    len = iguana_rwvarint(rwflag,serialized,&x);
    if ( rwflag == 0 )
        *int32p = (int32_t)x;
    return(len);
}

int32_t iguana_rwstr(int32_t rwflag,uint8_t *serialized,int32_t maxlen,char *endianedp)
{
    int32_t vlen; uint64_t n;
    if ( rwflag == 0 )
    {
        vlen = iguana_rwvarint(rwflag,serialized,&n);
        memcpy(endianedp,&serialized[vlen],n);
        ((uint8_t *)endianedp)[n] = 0;
    }
    else
    {
        n = strlen(endianedp);
        if ( n > maxlen )
            n = maxlen;
        vlen = iguana_rwvarint(rwflag,serialized,&n);
        memcpy(&serialized[vlen],endianedp,n);
    }
    return((int32_t)(n + vlen));
}

int32_t iguana_rwmem(int32_t rwflag,uint8_t *serialized,int32_t len,void *endianedp)
{
    if ( rwflag == 0 )
        memcpy(endianedp,serialized,len);
    else memcpy(serialized,endianedp,len);
    return(len);
}

int32_t iguana_rwaddr(int32_t rwflag,uint8_t *serialized,struct iguana_msgaddress *addr,int32_t protover)
{
    int32_t len = 0;
	if ( protover >= CADDR_TIME_VERSION )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(addr->nTime),&addr->nTime);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(addr->nServices),&addr->nServices);
    len += iguana_rwmem(rwflag,&serialized[len],sizeof(addr->ip),&addr->ip);
    if ( rwflag != 0 )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(addr->port),&addr->port);
    else
    {
        addr->port = (uint16_t)serialized[len++] << 8;
        addr->port += (uint16_t)serialized[len++];
    }
    return(len);
}

int32_t iguana_rwversion(int32_t rwflag,uint8_t *serialized,struct iguana_msgversion *msg,char *ipaddr)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->nVersion),&msg->nVersion);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->nServices),&msg->nServices);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->nTime),&msg->nTime);
    len += iguana_rwaddr(rwflag,&serialized[len],&msg->addrTo,MIN_PROTO_VERSION);
    len += iguana_rwaddr(rwflag,&serialized[len],&msg->addrFrom,MIN_PROTO_VERSION);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->nonce),&msg->nonce);
    len += iguana_rwstr(rwflag,&serialized[len],sizeof(msg->strSubVer),msg->strSubVer);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->nStartingHeight),&msg->nStartingHeight);
    if ( msg->nVersion > 70000 )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->relayflag),&msg->relayflag);
    if ( rwflag == 0 )
        printf("%-15s v.%llu srv.%llx %u ht.%llu [%s].R%d nonce.%llx\n",ipaddr,(long long)msg->nVersion,(long long)msg->nServices,(uint32_t)msg->nTime,(long long)msg->nStartingHeight,msg->strSubVer,msg->relayflag,(long long)msg->nonce);
    return(len);
}

int32_t iguana_rwblock(int32_t rwflag,bits256 *hash2p,uint8_t *serialized,struct iguana_msgblock *msg)
{
    int32_t len = 0; char blockhash[65]; uint64_t x;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->H.version),&msg->H.version);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->H.prev_block),msg->H.prev_block.bytes);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->H.merkle_root),msg->H.merkle_root.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->H.timestamp),&msg->H.timestamp);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->H.bits),&msg->H.bits);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->H.nonce),&msg->H.nonce);
    *hash2p = bits256_doublesha256(blockhash,serialized,len);
    //printf("len.%d: block version.%d timestamp.%u bits.%x nonce.%u prev.(%s) %llx blockhash.(%s) %llx\n",len,msg->H.version,msg->H.timestamp,msg->H.bits,msg->H.nonce,bits256_str(str,msg->H.prev_block),(long long)msg->H.merkle_root.txid,blockhash,(long long)hash2p->txid);
    if ( rwflag != 0 )
        x = msg->txn_count;
    len += iguana_rwvarint(rwflag,&serialized[len],&x);
    if ( rwflag == 0 )
    {
        char str[65];
        bits256_str(str,*hash2p);
        if ( x < 65536 )
            msg->txn_count = (uint16_t)x;
        else printf("txn_count overflow.%lld for %s\n",(long long)x,str);
    }
    //  ? 	txns 	tx[] 	Block transactions, in format of "tx" command
    return(len);
}

int32_t iguana_serialize_block(bits256 *hash2p,uint8_t serialized[sizeof(struct iguana_msgblock)],struct iguana_block *block)
{
    struct iguana_msgblock msg;
    memset(&msg,0,sizeof(msg));
    msg.H.version = block->RO.version;
    msg.H.prev_block = block->RO.prev_block;
    msg.H.merkle_root = block->RO.merkle_root;
    msg.H.timestamp = block->RO.timestamp;
    msg.H.bits = block->RO.bits;
    msg.H.nonce = block->RO.nonce;
    msg.txn_count = block->RO.txn_count;
    return(iguana_rwblock(1,hash2p,serialized,&msg));
}

int32_t iguana_rwblockhash(int32_t rwflag,uint8_t *serialized,uint32_t *nVersionp,uint32_t *varintp,bits256 *hashes,bits256 *stophash)
{
    int32_t i,len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(*nVersionp),nVersionp);
    len += iguana_rwvarint32(rwflag,&serialized[len],varintp);
    if ( *varintp < IGUANA_MAXBUNDLESIZE+1 )
    {
        for (i=0; i<*varintp; i++)
            len += iguana_rwbignum(rwflag,&serialized[len],sizeof(hashes[i]),hashes[i].bytes);
        len += iguana_rwbignum(rwflag,&serialized[len],sizeof(*stophash),stophash->bytes);
        //for (i=0; i<len; i++)
        //    printf("%02x ",serialized[i]);
        //printf("rwblockhash len.%d\n",len);
    } else printf("iguana_rwblockhash: illegal varint.%d\n",*varintp);
    return(len);
}

/*int32_t iguana_request_data(struct iguana_info *coin,struct iguana_peer *addr,bits256 *hashes,int32_t n,uint32_t type,int32_t forceflag)
{
    uint32_t len,i; uint8_t serialized[sizeof(struct iguana_msghdr) + (sizeof(uint32_t) + sizeof(bits256))*32 + sizeof(uint64_t)];
    if ( addr == 0 )
        return(-1);
    len = iguana_rwvarint32(1,&serialized[sizeof(struct iguana_msghdr)],(uint32_t *)&n);
    for (i=0; i<n; i++)
    {
        len += iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr) + len],sizeof(uint32_t),&type);
        len += iguana_rwbignum(1,&serialized[sizeof(struct iguana_msghdr) + len],sizeof(bits256),hashes[i].bytes);
    }
    //printf("iguana_request_data.%d %s ht.%d\n",n,bits256_str(hashes[0]),iguana_height(coin,hashes[0]));
    addr->getdatamillis = milliseconds();
    len = iguana_queue_send(coin,addr,serialized,"getdata",len,iguana_height(coin,hashes[n-1]),forceflag);
    return(len);
}*/

void iguana_gotversion(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msgversion *vers)
{
    uint8_t serialized[sizeof(struct iguana_msghdr)];
    //printf("gotversion from %s\n",addr->ipaddr);
    if ( (vers->nServices & NODE_NETWORK) == 0 )
        printf("other node.(%s) doesnt relay\n",addr->ipaddr);
    else if ( (vers->nServices & NODE_NETWORK) != 0 )//&& vers->nonce != coin->instance_nonce )
    {
        addr->protover = (vers->nVersion < PROTOCOL_VERSION) ? vers->nVersion : PROTOCOL_VERSION;
        addr->relayflag = vers->relayflag;
        addr->height = vers->nStartingHeight;
        addr->relayflag = 1;
        iguana_gotdata(coin,addr,addr->height);
        iguana_queue_send(coin,addr,serialized,"verack",0,0,0);
        //iguana_send_ping(coin,addr);
    } else printf("nServices.%llx nonce.%llu invalid version message from.(%s)\n",(long long)vers->nServices,(long long)vers->nonce,addr->ipaddr);
    if ( vers->nStartingHeight > coin->longestchain )
        coin->longestchain = vers->nStartingHeight;
    iguana_queue_send(coin,addr,serialized,"getaddr",0,0,0);
}

int32_t iguana_send_version(struct iguana_info *coin,struct iguana_peer *addr,uint64_t myservices)
{
  	int32_t len; struct iguana_msgversion msg; uint8_t serialized[sizeof(struct iguana_msghdr)+sizeof(msg)];
    memset(&msg,0,sizeof(msg));
	msg.nVersion = PROTOCOL_VERSION;
	msg.nServices = myservices;
	msg.nTime = (int64_t)time(NULL);
	msg.nonce = coin->instance_nonce;
	sprintf(msg.strSubVer,"/Satoshi:0.11.99/");
	msg.nStartingHeight = coin->blocks.hwmchain.height;
    iguana_gotdata(coin,addr,msg.nStartingHeight);
    len = iguana_rwversion(1,&serialized[sizeof(struct iguana_msghdr)],&msg,addr->ipaddr);
    return(iguana_queue_send(coin,addr,serialized,"version",len,0,1));
}

void iguana_gotverack(struct iguana_info *coin,struct iguana_peer *addr)
{
    uint8_t serialized[sizeof(struct iguana_msghdr)];
    if ( addr != 0 )
    {
        printf("gotverack from %s\n",addr->ipaddr);
        addr->A.nTime = (uint32_t)time(NULL);
        iguana_queue_send(coin,addr,serialized,"getaddr",0,0,0);
    }
}

void iguana_gotaddr(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msgaddress *A)
{
    char ipaddr[64]; uint32_t ipbits;
    iguana_rwnum(0,&A->ip[12],sizeof(uint32_t),&ipbits);
    expand_ipbits(ipaddr,ipbits);
    iguana_possible_peer(coin,ipaddr);
    //printf("gotaddr.(%s)\n",ipaddr);
}

void iguana_gotping(struct iguana_info *coin,struct iguana_peer *addr,uint64_t nonce,uint8_t *data)
{
    int32_t len; uint8_t serialized[sizeof(struct iguana_msghdr) + sizeof(nonce)];
    len = iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr)],sizeof(uint64_t),&nonce);
    if ( memcmp(data,&serialized[sizeof(struct iguana_msghdr)],sizeof(nonce)) != 0 )
        printf("ping ser error %llx != %llx\n",(long long)nonce,*(long long *)data);
    iguana_queue_send(coin,addr,serialized,"pong",len,0,0);
    iguana_queue_send(coin,addr,serialized,"getaddr",0,0,0);
}

int32_t iguana_send_ping(struct iguana_info *coin,struct iguana_peer *addr)
{
  	int32_t len; uint64_t nonce; uint8_t serialized[sizeof(struct iguana_msghdr) + sizeof(nonce)];
    if ( (nonce= addr->pingnonce) == 0 )
    {
        OS_randombytes((uint8_t *)&nonce,sizeof(nonce));
        addr->pingnonce = nonce;
        addr->pingtime = (uint32_t)time(NULL);
    }
    printf("pingnonce.%llx\n",(long long)nonce);
    len = iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr)],sizeof(uint64_t),&nonce);
    return(iguana_queue_send(coin,addr,serialized,"ping",len,0,0));
}

void iguana_gotpong(struct iguana_info *coin,struct iguana_peer *addr,uint64_t nonce)
{
    if ( addr->sendmillis != 0 )
    {
        addr->pingtime = (OS_milliseconds() - addr->sendmillis) + 1;
        addr->pingsum += addr->pingtime, addr->numpings++;
        printf("%s pingtime %.0f numpings.%d [%.3f] ",addr->ipaddr,addr->pingtime,addr->numpings,addr->pingsum/addr->numpings);
    }
    if ( nonce != addr->pingnonce )
    {
        printf("pong received invalid pingnonce (%s) %llx vs %llx\n",addr->ipaddr,(long long)addr->pingnonce,(long long)nonce);
    } else printf("(%s) pong verified with pingnonce.%llx\n",addr->ipaddr,(long long)addr->pingnonce);
    addr->pingnonce = 0;
    addr->sendmillis = 0;
}

int32_t iguana_gethdrs(struct iguana_info *coin,uint8_t *serialized,char *cmd,char *hashstr)
{
    uint32_t len,n; bits256 hash2; bits256 zero;
    decode_hex(hash2.bytes,sizeof(hash2),hashstr);
    memset(zero.bytes,0,sizeof(zero));
    n = 0;
    len = iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr)],sizeof(uint32_t),&n);
    n++;
    len += iguana_rwvarint32(1,&serialized[sizeof(struct iguana_msghdr) + len],(uint32_t *)&n);
    len += iguana_rwbignum(1,&serialized[sizeof(struct iguana_msghdr) + len],sizeof(bits256),hash2.bytes);
    len += iguana_rwbignum(1,&serialized[sizeof(struct iguana_msghdr) + len],sizeof(bits256),(uint8_t *)zero.bytes);
    return(iguana_sethdr((void *)serialized,coin->chain->netmagic,cmd,&serialized[sizeof(struct iguana_msghdr)],len));
}

int32_t iguana_getdata(struct iguana_info *coin,uint8_t *serialized,int32_t type,char *hashstr)
{
    uint32_t len,i,n=1; bits256 hash2;
    decode_hex(hash2.bytes,sizeof(hash2),hashstr);
    len = iguana_rwvarint32(1,&serialized[sizeof(struct iguana_msghdr)],(uint32_t *)&n);
    for (i=0; i<n; i++)
    {
        len += iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr) + len],sizeof(uint32_t),&type);
        len += iguana_rwbignum(1,&serialized[sizeof(struct iguana_msghdr) + len],sizeof(bits256),hash2.bytes);
    }
    return(iguana_sethdr((void *)serialized,coin->chain->netmagic,"getdata",&serialized[sizeof(struct iguana_msghdr)],len));
}

int32_t iguana_rwvin(int32_t rwflag,struct OS_memspace *mem,uint8_t *serialized,struct iguana_msgvin *msg)
{
    int32_t len = 0;
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->prev_hash),msg->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->prev_vout),&msg->prev_vout);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->scriptlen);
    if ( rwflag == 0 )
        msg->script = iguana_memalloc(mem,msg->scriptlen,1);
    len += iguana_rwmem(rwflag,&serialized[len],msg->scriptlen,msg->script);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->sequence),&msg->sequence);
    //char str[65]; printf("MSGvin.(%s/v%d) script[%d]\n",bits256_str(str,msg->prev_hash),msg->prev_vout,msg->scriptlen);
    //int i; for (i=0; i<msg->scriptlen; i++)
    // printf("%02x ",msg->script[i]);
    //printf(" inscriptlen.%d, prevhash.%llx prev_vout.%d | ",msg->scriptlen,(long long)msg->prev_hash.txid,msg->prev_vout);
    return(len);
}

int32_t iguana_rwvout(int32_t rwflag,struct OS_memspace *mem,uint8_t *serialized,struct iguana_msgvout *msg)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->value),&msg->value);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->pk_scriptlen);
    if ( rwflag == 0 )
        msg->pk_script = iguana_memalloc(mem,msg->pk_scriptlen,1);
    len += iguana_rwmem(rwflag,&serialized[len],msg->pk_scriptlen,msg->pk_script);
    //printf("(%.8f scriptlen.%d) ",dstr(msg->value),msg->pk_scriptlen);
    //int i; for (i=0; i<msg->pk_scriptlen; i++)
    //    printf("%02x",msg->pk_script[i]);
    //printf("\n");
    return(len);
}

int32_t iguana_rwtx(int32_t rwflag,struct OS_memspace *mem,uint8_t *serialized,struct iguana_msgtx *msg,int32_t maxsize,bits256 *txidp,int32_t height,int32_t hastimestamp)
{
    int32_t i,len = 0; uint8_t *txstart = serialized; char txidstr[65];
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->version),&msg->version);
    if ( hastimestamp != 0 )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->timestamp),&msg->timestamp);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_in);
    //printf("version.%d ",msg->version);
    if ( msg->tx_in > 0 && msg->tx_out*100 < maxsize )
    {
        if ( rwflag == 0 )
            msg->vins = iguana_memalloc(mem,msg->tx_in * sizeof(*msg->vins),1);
        for (i=0; i<msg->tx_in; i++)
            len += iguana_rwvin(rwflag,mem,&serialized[len],&msg->vins[i]);
        //printf("numvins.%d\n",msg->tx_in);
    }
    else
    {
        printf("invalid tx_in.%d\n",msg->tx_in);
        return(-1);
    }
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_out);
    if ( msg->tx_out > 0 && msg->tx_out*32 < maxsize )
    {
        //printf("numvouts.%d ",msg->tx_out);
        if ( rwflag == 0 )
            msg->vouts = iguana_memalloc(mem,msg->tx_out * sizeof(*msg->vouts),1);
        for (i=0; i<msg->tx_out; i++)
            len += iguana_rwvout(rwflag,mem,&serialized[len],&msg->vouts[i]);
    }
    else
    {
        printf("invalid tx_out.%d\n",msg->tx_out);
        return(-1);
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->lock_time),&msg->lock_time);
    *txidp = bits256_doublesha256(txidstr,txstart,len);
    msg->allocsize = len;
    return(len);
}

char *iguana_txbytes(struct iguana_info *coin,bits256 *txidp,struct iguana_txid *tx,int32_t height)
{
    int32_t i,rwflag=1,len = 0; uint8_t *serialized = coin->blockspace; char asmstr[512],txidstr[65],*txbytes = 0;
    uint32_t numvins,numvouts; struct iguana_msgvin vin; struct iguana_msgvout vout; uint8_t space[8192];
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(tx->version),&tx->version);
    if ( coin->chain->hastimestamp != 0 )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(tx->timestamp),&tx->timestamp);
    numvins = tx->numvins, numvouts = tx->numvouts;
    len += iguana_rwvarint32(rwflag,&serialized[len],&numvins);
    for (i=0; i<numvins; i++)
    {
        iguana_vinset(coin,height,&vin,tx,i);
        len += iguana_rwvin(rwflag,0,&serialized[len],&vin);
    }
    len += iguana_rwvarint32(rwflag,&serialized[len],&numvouts);
    for (i=0; i<numvouts; i++)
    {
        iguana_voutset(coin,space,asmstr,height,&vout,tx,i);
        len += iguana_rwvout(rwflag,0,&serialized[len],&vout);
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(tx->locktime),&tx->locktime);
    *txidp = bits256_doublesha256(txidstr,serialized,len);
    if ( memcmp(txidp,tx->txid.bytes,sizeof(*txidp)) != 0 )
    {
        printf("error generating txbytes\n");
        return(0);
    }
    txbytes = mycalloc('x',1,len*2+1);
    init_hexbytes_noT(txbytes,serialized,len*2+1);
    return(txbytes);
}

int32_t iguana_gentxarray(struct iguana_info *coin,struct OS_memspace *mem,struct iguana_txblock *txdata,int32_t *lenp,uint8_t *data,int32_t datalen)
{
    struct iguana_msgtx *tx; bits256 hash2; struct iguana_msgblock msg; int32_t i,n,len,numvouts,numvins;
    memset(&msg,0,sizeof(msg));
    len = iguana_rwblock(0,&hash2,data,&msg);
    iguana_blockconv(&txdata->block,&msg,hash2,-1);
    tx = iguana_memalloc(mem,msg.txn_count*sizeof(*tx),1);
    for (i=numvins=numvouts=0; i<msg.txn_count; i++)
    {
        if ( (n= iguana_rwtx(0,mem,&data[len],&tx[i],datalen - len,&tx[i].txid,txdata->block.height,coin->chain->hastimestamp)) < 0 )
            break;
        numvouts += tx[i].tx_out;
        numvins += tx[i].tx_in;
        len += n;
    }
    if ( coin->chain->hastimestamp != 0 && len != datalen && data[len] == (datalen - len - 1) )
    {
        //printf("\n>>>>>>>>>>> len.%d vs datalen.%d [%d]\n",len,datalen,data[len]);
        memcpy(txdata->space,&data[len],datalen-len);
        len += (datalen-len);
        txdata->extralen = (datalen - len);
    } else txdata->extralen = 0;
    txdata->recvlen = len;
    txdata->numtxids = msg.txn_count;
    txdata->numunspents = numvouts;
    txdata->numspends = numvins;
    return(len);
}

int32_t iguana_send_hashes(struct iguana_info *coin,char *command,struct iguana_peer *addr,bits256 stophash,bits256 *hashes,int32_t n)
{
  	uint32_t len,nVersion,varint; int32_t retval = -1; uint8_t *serialized; long size;
    size = sizeof(struct iguana_msghdr) + sizeof(uint64_t) + 1 + sizeof(bits256)*(n+1);
    if ( (varint= n) <= IGUANA_MAXINV )
    {
        serialized = mycalloc('h',1,size);
        nVersion = 0;
        len = iguana_rwblockhash(1,&serialized[sizeof(struct iguana_msghdr)],&nVersion,&varint,hashes,&stophash);
        //printf("%s send_hashes.%d %s height.%d\n",addr->ipaddr,n,bits256_str(hashes[0]),iguana_height(coin,hashes[0]));
        retval = iguana_queue_send(coin,addr,serialized,command,len,0,0);
        myfree(serialized,size);
    } else printf("iguana_send_hashes: unexpected n.%d\n",n);
    return(retval);
}

int32_t iguana_parser(struct iguana_info *coin,struct iguana_peer *addr,struct OS_memspace *rawmem,struct OS_memspace *txmem,struct OS_memspace *hashmem,struct iguana_msghdr *H,uint8_t *data,int32_t datalen)
{
    uint8_t serialized[512];
    int32_t i,retval,srvmsg,bloom,intvectors,len= -100; uint64_t nonce,x; uint32_t type; bits256 hash2;
    bloom = intvectors = srvmsg = -1;
    if ( addr != 0 )
    {
        addr->lastcontact = (uint32_t)time(NULL);
        strcpy(addr->lastcommand,H->command);
    }
    retval = 0;
    //printf("%s parse.(%s)\n",addr->ipaddr,H->command);
    if ( strcmp(H->command,"version") == 0 )
    {
        struct iguana_msgversion recvmv;
        if ( addr != 0 )
        {
            len = iguana_rwversion(0,data,&recvmv,addr->ipaddr);
            if ( len == datalen )
                iguana_gotversion(coin,addr,&recvmv);
            //printf("deser.(%s) len.%d datalen.%d\n",recvmv.H.command,len,datalen);
            addr->msgcounts.version++;
        }
    }
    else if ( strcmp(H->command,"verack") == 0 )
    {
        if ( addr != 0 )
        {
            iguana_gotverack(coin,addr);
            addr->msgcounts.verack++;
        }
        len = 0;
    }
    else if ( strcmp(H->command,"ping") == 0 )
    {
        if ( datalen == sizeof(uint64_t) && addr != 0 )
        {
            len = iguana_rwnum(0,data,sizeof(uint64_t),&nonce);
            if ( addr != 0 )
            {
                //printf("%u got nonce.%llx from %s\n",(uint32_t)time(NULL),(long long)nonce,addr->ipaddr);
                iguana_gotping(coin,addr,nonce,data);
                addr->msgcounts.ping++;
            }
            iguana_queue_send(coin,addr,serialized,"getaddr",0,0,0);
        }
    }
    else if ( strcmp(H->command,"pong") == 0 )
    {
        len = 0;
        if ( datalen == sizeof(uint64_t) )
        {
            len = iguana_rwnum(0,data,sizeof(uint64_t),&nonce);
            iguana_gotpong(coin,addr,nonce);
        } else printf("unexpected pong datalen.%d\n",datalen);
        if ( len == datalen && addr != 0 )
            addr->msgcounts.pong++;
        iguana_queue_send(coin,addr,serialized,"getaddr",0,0,0);
    }
    else if ( strcmp(H->command,"addr") == 0 )
    {
        struct iguana_msgaddress A;
        len = iguana_rwvarint(0,data,&x);
        for (i=0; i<x; i++)
        {
            memset(&A,0,sizeof(A));
            if ( addr != 0 )
                len += iguana_rwaddr(0,&data[len],&A,(int32_t)addr->protover);
            iguana_gotaddr(coin,addr,&A);
        }
        if ( len == datalen && addr != 0 )
        {
            addr->lastgotaddr = (uint32_t)time(NULL);
            addr->msgcounts.addr++;
        }
        //printf("%s -> addr datalen.%d num.%d\n",addr->ipaddr,datalen,(int32_t)x);
    }
    else if ( strcmp(H->command,"headers") == 0 )
    {
        struct iguana_msgblock msg; struct iguana_block *blocks; uint32_t n;
        len = iguana_rwvarint32(0,data,&n);
        if ( n <= IGUANA_MAXINV )
        {
            blocks = mycalloc('i',1,sizeof(*blocks) * n);
            for (i=0; i<n; i++)
            {
                len += iguana_rwblock(0,&hash2,&data[len],&msg);
                iguana_blockconv(&blocks[i],&msg,hash2,-1);
            }
            //printf("GOT HEADERS n.%d len.%d\n",n,len);
            iguana_gotheadersM(coin,addr,blocks,n);
            //myfree(blocks,sizeof(*blocks) * n);
            if ( len == datalen && addr != 0 )
                addr->msgcounts.headers++;
        } else printf("got unexpected n.%d for headers\n",n);
    }
    else if ( strcmp(H->command,"tx") == 0 )
    {
        struct iguana_msgtx *tx;
        iguana_memreset(rawmem);
        tx = iguana_memalloc(rawmem,sizeof(*tx),1);//mycalloc('u',1,sizeof(*tx));
        len = iguana_rwtx(0,rawmem,data,tx,datalen,&tx->txid,-1,coin->chain->hastimestamp);
        iguana_gotunconfirmedM(coin,addr,tx,data,datalen);
        printf("tx datalen.%d vs len.%d\n",datalen,len);
        addr->msgcounts.tx++;
    }
    else if ( strcmp(H->command,"block") == 0 )
    {
        struct iguana_txblock txdata;
        if ( addr != 0 )
            addr->msgcounts.block++;
        iguana_memreset(rawmem), iguana_memreset(txmem);//, iguana_memreset(hashmem);
        memset(&txdata,0,sizeof(txdata));
        if ( (len= iguana_gentxarray(coin,rawmem,&txdata,&len,data,datalen)) == datalen )
            iguana_gotblockM(coin,addr,&txdata,rawmem->ptr,H,data,datalen);
        else printf("parse error block txn_count.%d, len.%d vs datalen.%d\n",txdata.block.RO.txn_count,len,datalen);
    }
    else if ( strcmp(H->command,"reject") == 0 )
    {
        for (i=0; i<datalen; i++)
            printf("%02x ",data[i]);
        printf("reject.(%s) datalen.%d\n",data+1,datalen);
        len = datalen;
        if ( len == datalen && addr != 0 )
            addr->msgcounts.reject++;
    }
    else if ( strcmp(H->command,"alert") == 0 )
    {
        for (i=0; i<datalen; i++)
            printf("%02x ",data[i]);
        printf("alert.(%s)\n",data+1);
        len = datalen;
        if ( len == datalen && addr != 0 )
            addr->msgcounts.alert++;
    }
    else if ( addr != 0 )
    {
        if ( strcmp(H->command,"inv") == 0 )
            intvectors = 'I', addr->msgcounts.inv++;
        else if ( strcmp(H->command,"notfound") == 0 ) // for servers
            intvectors = 'N', addr->msgcounts.notfound++;
        else if ( strcmp(H->command,"getdata") == 0 ) // for servers
            intvectors = srvmsg = 'D', addr->msgcounts.getdata++;
        else if ( strcmp(H->command,"getblocks") == 0 ) // for servers
            srvmsg = 'B', addr->msgcounts.getblocks++;
        else if ( strcmp(H->command,"getheaders") == 0 ) // for servers
            srvmsg = 'H', addr->msgcounts.getheaders++;
        else if ( strcmp(H->command,"getaddr") == 0 ) // for servers
            srvmsg = 'A', addr->msgcounts.getaddr++;
        else if ( strcmp(H->command,"mempool") == 0 ) // for servers
            srvmsg = 'M', addr->msgcounts.mempool++;
        else if ( strcmp(H->command,"filterload") == 0 ) // for bloom
            bloom = 'L', addr->msgcounts.filterload++;
        else if ( strcmp(H->command,"filteradd") == 0 ) // for bloom
            bloom = 'A', addr->msgcounts.filteradd++;
        else if ( strcmp(H->command,"filterclear") == 0 ) // for bloom
            bloom = 'C', addr->msgcounts.filterclear++;
        else if ( strcmp(H->command,"merkleblock") == 0 ) // for bloom
            bloom = 'M', addr->msgcounts.merkleblock++;
    }
    if ( bloom >= 0 || srvmsg >= 0 )
        len = datalen; // just mark as valid
    if ( intvectors >= 0 )
    {
        bits256 *txids=0,*blockhashes=0,hash; int32_t n,m;
        len = n = m = 0;
        len += iguana_rwvarint(0,&data[len],&x);
        for (i=0; i<x; i++)
        {
            len += iguana_rwnum(0,&data[len],sizeof(uint32_t),&type);
            len += iguana_rwbignum(0,&data[len],sizeof(bits256),hash.bytes);
            if ( type == MSG_TX )
            {
                if ( txids == 0 )
                    txids = mycalloc('t',(int32_t)x+1,sizeof(*txids));
                txids[m++] = hash;
                if ( (rand() % 1000) == 0 && i == x-1 )
                    printf("%s iv.%c %d of %d: tx.%llx len.%d\n",addr->ipaddr,intvectors,i,(int32_t)x,(long long)hash.txid,len);
            }
            else if ( type == MSG_BLOCK )
            {
                if ( blockhashes == 0 )
                {
                    blockhashes = mycalloc('f',(int32_t)x+1,sizeof(*blockhashes));
                    n = 1;
                }
                blockhashes[n++] = hash;
            }
            else if ( type == MSG_FILTERED_BLOCK )
                printf("iv.%d %d of %d: merkle.%llx\n",intvectors,i,(int32_t)x,(long long)hash.txid);
            else printf("what type is %d\n",type);
        }
        if ( intvectors == 'I' )
        {
            if ( n > 0 )
            {
                if ( n != x+1 )
                {
                    printf("n.%d != x.%d -> realloc blockhashes\n",n,(int32_t)x+1);
                    blockhashes = myrealloc('f',blockhashes,(int32_t)((x+1)*sizeof(*blockhashes)),n*sizeof(*blockhashes));
                } // else printf("n.%d == x.%d\n",n,(int32_t)x);
                if ( 1 )
                    iguana_gotblockhashesM(coin,addr,blockhashes,n), blockhashes = 0;
                else iguana_send_hashes(coin,"getblocks",addr,blockhashes[0],&blockhashes[1],n);
            }
            if ( m > 0 )
            {
                if ( m != x )
                    txids = myrealloc('t',txids,(int32_t)((x+1)*sizeof(*txids)),(m+1)*sizeof(*txids));
                iguana_gottxidsM(coin,addr,txids,m), txids = 0;
            }
        }
        if ( txids != 0 )
            myfree(txids,sizeof(*txids) * (x+1));
        if ( blockhashes != 0 )
            myfree(blockhashes,sizeof(*blockhashes) * (x+1));
        //printf("intvectors.%c datalen.%d\n",intvectors,datalen);
    }
    if ( len != datalen && len != datalen-1 )
    {
        //printf("error.(%s) (%s): len.%d != datalen.%d\n",H->command,addr->ipaddr,len,datalen);
        //for (i=0; i<len; i++)
        //    printf("%02x",data[i]);
        if ( strcmp(H->command,"addr") != 0 )
            printf("%s.%s len mismatch %d != %d\n",addr!=0?addr->ipaddr:"local",H->command,len,datalen);
    }
    else if ( len == datalen-1 )
    {
        printf("extra byte.[%02x] command.%s len.%d datalen.%d\n",data[datalen-1],H->command,len,datalen);
        //retval = -1;
    }
    return(retval);
}

