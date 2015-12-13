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

uint64_t Tx_allocated,Tx_allocsize,Tx_freed,Tx_freesize;

int64_t iguana_MEMallocated(struct iguana_info *coin)
{
    int64_t total = coin->TMPallocated;
    if ( Tx_allocsize > Tx_freesize )
        total += (Tx_allocsize - Tx_freesize);
    //total += coin->R.RSPACE.openfiles * coin->R.RSPACE.size;
    //total += iguana_packetsallocated(coin);
    return(total);
}
// two passes to check data size
int32_t iguana_rwvin(int32_t rwflag,uint8_t *serialized,struct iguana_msgvin *msg)
{
    int32_t len = 0;
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->prev_hash),msg->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->prev_vout),&msg->prev_vout);
    //printf("vin.(%s) %d\n",bits256_str(msg->prev_hash),msg->prev_vout);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->scriptlen);
    if ( rwflag == 0 )
        msg->script = mycalloc('s',1,msg->scriptlen);
    len += iguana_rwmem(rwflag,&serialized[len],msg->scriptlen,msg->script);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->sequence),&msg->sequence);
    //int i; for (i=0; i<msg->scriptlen; i++)
    // printf("%02x ",msg->script[i]);
    //printf(" inscriptlen.%d, prevhash.%llx prev_vout.%d | ",msg->scriptlen,(long long)msg->prev_hash.txid,msg->prev_vout);
    return(len);
}

int32_t iguana_rwvout(int32_t rwflag,uint8_t *serialized,struct iguana_msgvout *msg)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->value),&msg->value);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->pk_scriptlen);
    if ( rwflag == 0 )
        msg->pk_script = mycalloc('s',1,msg->pk_scriptlen);
    len += iguana_rwmem(rwflag,&serialized[len],msg->pk_scriptlen,msg->pk_script);
    //printf("(%.8f scriptlen.%d) ",dstr(msg->value),msg->pk_scriptlen);
    //int i; for (i=0; i<msg->pk_scriptlen; i++)
    //    printf("%02x",msg->pk_script[i]);
    //printf("\n");
    return(len);
}

int32_t iguana_rwtx(int32_t rwflag,uint8_t *serialized,struct iguana_msgtx *msg,int32_t maxsize,bits256 *txidp,int32_t height,int32_t hastimestamp)
{
    int32_t i,len = 0; uint8_t *txstart = serialized; char txidstr[65]; uint32_t timestamp;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->version),&msg->version);
    if ( hastimestamp != 0 )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(timestamp),&timestamp);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_in);
    //printf("version.%d ",msg->version);
    if ( msg->tx_in > 0 && msg->tx_out*100 < maxsize )
    {
        if ( rwflag == 0 )
            msg->vins = mycalloc('v',msg->tx_in,sizeof(*msg->vins));
        for (i=0; i<msg->tx_in; i++)
            len += iguana_rwvin(rwflag,&serialized[len],&msg->vins[i]);
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
            msg->vouts = mycalloc('v',msg->tx_out,sizeof(*msg->vouts));
        for (i=0; i<msg->tx_out; i++)
            len += iguana_rwvout(rwflag,&serialized[len],&msg->vouts[i]);
    }
    else
    {
        printf("invalid tx_out.%d\n",msg->tx_out);
        return(-1);
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->lock_time),&msg->lock_time);
    *txidp = bits256_doublesha256(txidstr,txstart,len);
    //printf("txid.(%s) len.%d\n",bits256_str(*txidp),len);
    msg->allocsize = len;
    Tx_allocated++, Tx_allocsize += len;
    if ( ((Tx_allocated + Tx_freed) % 10000000) == 0 )
        printf("h.%u len.%d (%llu - %llu) %lld (%llu - %llu)\n",height,len,(long long)Tx_allocated,(long long)Tx_freed,(long long)(Tx_allocated - Tx_freed),(long long)Tx_allocsize,(long long)Tx_freesize);
    return(len);
}

void iguana_freetx(struct iguana_msgtx *tx,int32_t n)
{
    int32_t i,j; struct iguana_msgtx *origtx = tx;
    for (j=0; j<n; j++,tx++)
    {
        Tx_freed++, Tx_freesize += tx->allocsize;
        if ( tx->vins != 0 )
        {
            for (i=0; i<tx->tx_in; i++)
                if ( tx->vins[i].script != 0 )
                    myfree(tx->vins[i].script,tx->vins[i].scriptlen);
            myfree(tx->vins,tx->tx_in * sizeof(*tx->vins));
        }
        if ( tx->vouts != 0 )
        {
            for (i=0; i<tx->tx_out; i++)
                if ( tx->vouts[i].pk_script != 0 )
                    myfree(tx->vouts[i].pk_script,tx->vouts[i].pk_scriptlen);
            myfree(tx->vouts,tx->tx_out * sizeof(*tx->vouts));
        }
    }
    myfree(origtx,sizeof(*origtx) * n);
}

struct iguana_msgtx *iguana_gentxarray(struct iguana_info *coin,int32_t *lenp,struct iguana_block *block,uint8_t *data,int32_t datalen,uint8_t extra[256])
{
    struct iguana_msgtx *tx; bits256 hash2; struct iguana_msgblock msg; int32_t i,n,len;
    memset(&msg,0,sizeof(msg));
    len = iguana_rwblock(0,&hash2,data,&msg);
    iguana_convblock(block,&msg,hash2,block->height,block->L.numtxids,block->L.numunspents,block->L.numspends,block->L.PoW);
    block->txn_count = msg.txn_count;
    block->height = iguana_setdependencies(coin,block);
    //printf("iguana_gentxarray block %s prev.(%s): height.%d firsttxidind.%d firstvout.%d firstvin.%d PoW %f numtx.%d\n",bits256_str2(hash2),bits256_str(msg.H.prev_block),block->height,block->L.firsttxidind,block->L.firstvout,block->L.firstvin,block->L.PoW,msg.txn_count);
    iguana_convblock(block,&msg,hash2,block->height,block->L.numtxids,block->L.numunspents,block->L.numspends,block->L.PoW);
    tx = mycalloc('t',msg.txn_count,sizeof(*tx));
    for (i=0; i<msg.txn_count; i++)
    {
        if ( (n= iguana_rwtx(0,&data[len],&tx[i],datalen - len,&tx[i].txid,block->height,coin->chain->hastimestamp)) < 0 )
            break;
        len += n;
    }
    if ( coin->chain->hastimestamp != 0 && len != datalen && data[len] == (datalen - len - 1) )
    {
        //printf("\n>>>>>>>>>>> len.%d vs datalen.%d [%d]\n",len,datalen,data[len]);
        memcpy(extra,&data[len],datalen-len);
        len += (datalen-len);
    }
    *lenp = len;
    return(tx);
}

struct iguana_bundlereq *iguana_bundlereq(struct iguana_info *coin,struct iguana_peer *addr,int32_t type,int32_t datalen)
{
    struct iguana_bundlereq *req; int32_t allocsize;
    allocsize = (uint32_t)sizeof(*req) + datalen;
    req = mycalloc(type,1,allocsize);
    req->allocsize = allocsize;
    req->datalen = datalen;
    req->addr = addr;
    req->coin = coin;
    req->type = type;
    return(req);
}

void iguana_gottxidsM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *txids,int32_t n)
{
    struct iguana_bundlereq *req;
    printf("got %d txids from %s\n",n,addr->ipaddr);
    req = iguana_bundlereq(coin,addr,'T',0);
    req->hashes = txids, req->n = n;
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotunconfirmedM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msgtx *tx,uint8_t *data,int32_t datalen)
{
    struct iguana_bundlereq *req;
    printf("%s unconfirmed.%s\n",addr->ipaddr,bits256_str(tx->txid));
    req = iguana_bundlereq(coin,addr,'U',datalen);
    req->n = datalen;
    memcpy(req->serialized,data,datalen);
    iguana_freetx(tx,1);
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotblockM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *block,struct iguana_msgtx *txarray,int32_t numtx,uint8_t *data,int32_t datalen,uint8_t extra[256])
{
    struct iguana_bundlereq *req; int32_t i;
    if ( 0 )
    {
        for (i=0; i<extra[0]; i++)
            if ( extra[i] != 0 )
                break;
        if ( i != extra[0] )
        {
            for (i=0; i<extra[0]; i++)
                printf("%02x ",extra[i]);
            printf("extra\n");
        }
    }
    if ( addr != 0 )
    {
        if ( addr->pendblocks > 0 )
            addr->pendblocks--;
        addr->lastblockrecv = (uint32_t)time(NULL);
        addr->recvblocks += 1.;
        addr->recvtotal += datalen;
    }
    coin->recvcount++;
    coin->recvtime = (uint32_t)time(NULL);
    req = iguana_bundlereq(coin,addr,'B',datalen);
    req->blocks = block, req->n = datalen;
    memcpy(req->serialized,data,datalen);
    //printf("test emit txarray[%d] %p\n",numtx,block);
    block->txn_count = req->numtx = numtx;
    iguana_freetx(txarray,numtx);
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotheadersM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *blocks,int32_t n)
{
    struct iguana_bundlereq *req;
    if ( addr != 0 )
    {
        addr->recvhdrs++;
        if ( addr->pendhdrs > 0 )
            addr->pendhdrs--;
        //printf("%s blocks[%d] ht.%d gotheaders pend.%d %.0f\n",addr->ipaddr,n,blocks[0].height,addr->pendhdrs,milliseconds());
    }
    req = iguana_bundlereq(coin,addr,'H',0);
    req->blocks = blocks, req->n = n;
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotblockhashesM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *blockhashes,int32_t n)
{
    struct iguana_bundlereq *req;
    if ( addr != 0 )
    {
        addr->recvhdrs++;
        if ( addr->pendhdrs > 0 )
            addr->pendhdrs--;
    }
    req = iguana_bundlereq(coin,addr,'S',0);
    req->hashes = blockhashes, req->n = n;
    //printf("bundlesQ blockhashes.%p[%d]\n",blockhashes,n);
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}
